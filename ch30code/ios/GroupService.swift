// GroupService.swift
// Listing 30.3 (continued) — Swift: the same group service on iOS, against the
// UniFFI-generated Swift API of Listing 30.1. The database is the GRDB
// DatabasePool of Listing 28.7 (core.db), so the app and the NSE share MLS
// state under the same IMMEDIATE rule. ActiveTransaction: `enum
// ActiveTransaction { @TaskLocal static var current: Database? }`, set only on
// GRDB's writer.
import Foundation
import GRDB
import MurmurGroups

final class GRDBMlsStore: MlsStore, @unchecked Sendable {
    private let db: DatabasePool
    init(_ db: DatabasePool) throws {
        self.db = db
        try db.write { try $0.execute(
            sql: "CREATE TABLE IF NOT EXISTS mls_kv (k BLOB PRIMARY KEY, v " +
            "BLOB NOT NULL)") }
    }
    func loadAll() -> [Kv] {
        (try? db.read { try Row.fetchAll($0,
            sql: "SELECT k, v FROM mls_kv").map { Kv(key: $0["k"],
            value: $0["v"]) } }) ?? []
    }
    /// Called by the core INSIDE `ActiveTransaction.current` when the receive
    /// loop holds one.
    func commit(puts: [Kv], deletes: [Data]) throws {
        let apply: (Database) throws -> Void = { db in
            for kv in puts { try db.execute(
                sql: "INSERT OR REPLACE INTO mls_kv VALUES (?,?)",
                arguments: [kv.key, kv.value]) }
            for k in deletes { try db.execute(
                sql: "DELETE FROM mls_kv WHERE k=?", arguments: [k]) }
        }
        do {
            // join the caller's transaction
            if let open = ActiveTransaction.current { try apply(open) }
            // GRDB write = BEGIN IMMEDIATE
            else { try db.write { try apply($0) } }
        } catch { throw GroupError.Storage(msg: "\(error)") }
    }
}

final class VerifiedDirectory: IdentityDirectory, @unchecked Sendable {
    let contacts: ContactsStore
    init(_ c: ContactsStore) { contacts = c }
    func identityKey(account: String,
        device: String) -> Data? { contacts.verifiedIdentityKey(
        account: account, device: device) }
}

final class IdentityBinder: CredentialBinder, @unchecked Sendable {
    let ik: IdentityKeyHolder
    init(_ ik: IdentityKeyHolder) { self.ik = ik }
    // SE-unwrapped for this call only
    func bind(message: Data) -> Data { ik.xeddsaSign(message) }
}

actor GroupService {
    private let db: DatabasePool, api: MurmurAPIClient, account: String,
        device: String
    private let store: GRDBMlsStore, directory: VerifiedDirectory,
        binder: IdentityBinder
    private var core: MurmurGroups

    init(db: DatabasePool, api: MurmurAPIClient, contacts: ContactsStore,
        account: String, device: String,
        ik: IdentityKeyHolder) throws {
        self.db = db; self.api = api; self.account = account; self.device =
            device
        store = try GRDBMlsStore(db); directory = VerifiedDirectory(
            contacts); binder = IdentityBinder(ik)
        core = try MurmurGroups.open(account: account, device: device,
            store: store, directory: directory, binder: binder)
    }

    private func submit(_ gid: Data, joiners: [String] = [],
        removed: [String] = [],
        _ build: () throws -> CommitOutput) async throws -> UInt64 {
        for _ in 0..<3 {
            let out = try build()
            var members = try core.members(groupId: gid).filter {
                !removed.contains($0) }
                .map { String($0.split(separator: "/", maxSplits: 1)[1]) }
            members += joiners.filter { !members.contains($0) }
            do {
                try await api.submitCommit(out.commit, members: members,
                    joiners: joiners, welcome: out.welcome)
                return try core.mergePending(groupId: gid)
            } catch APIError.staleEpoch {
                try core.clearPending(groupId: gid)
                // process the winner, then rebuild
                _ = try await receive()
            } catch {
                try? core.clearPending(groupId: gid); throw error
            }
        }
        throw APIError.gaveUp
    }

    func removeOwnDeviceEverywhere(_ lost: String) async throws {
        for gid in core.groupIds() where try core.members(
            groupId: gid).contains("\(account)/\(lost)") {
            _ = try await submit(gid,
                removed: ["\(account)/\(lost)"]) { try core.removeMembers(
                groupId: gid, members: ["\(account)/\(lost)"]) }
        }
    }

    func receive() async throws -> [Processed] {
        var out: [Processed] = [], acked: [Data] = []
        for env in try await api.fetchGroupEnvelopes() {
            do {
                if let r = try processInTransaction(guid: env.guid,
                    isWelcome: env.isWelcome,
                    content: env.content) { out.append(r) }
            } catch is GroupError {
                core = try MurmurGroups.open(account: account, device: device,
                    store: store, directory: directory, binder: binder)
                // reloaded core; the queue moves on
                try await db.write { try Dedupe.markFailed($0, env.guid) }
            }
            acked.append(env.guid)
        }
        if !acked.isEmpty { try await api.ack(acked) }
        return out
    }

    /// Synchronous on purpose: in an async context `db.write` would pick GRDB's
    /// async overload, whose closure runs off the actor and cannot touch
    /// `core`. Here MLS processing, the inbox insert and the dedupe mark share
    /// ONE IMMEDIATE transaction on the actor.
    private func processInTransaction(guid: Data, isWelcome: Bool,
        content: Data) throws -> Processed? {
        // BEGIN IMMEDIATE … COMMIT
        try db.write { db in
            try ActiveTransaction.$current.withValue(db) {
                guard try !Dedupe.seen(db, guid) else { return nil }
                let r = isWelcome ? try joined(content) : try core.process(
                    wire: content)
                if case let .application(gid, sender,
                    plaintext) = r { try Inbox.insert(db, gid, sender,
                    plaintext) }
                if case let .rejected(gid,
                    reason) = r { try SecurityLog.groupRejected(db, gid,
                    reason) }
                try Dedupe.mark(db, guid)
                return r
            }
        }
    }

    private func joined(_ welcome: Data) throws -> Processed {
        let gid = try core.join(welcome: welcome)
        return .commitMerged(groupId: gid, epoch: try core.epoch(groupId: gid),
            added: [], removed: [])
    }
}
