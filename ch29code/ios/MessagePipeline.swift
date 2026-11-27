// MessagePipeline.swift
// Listing 29.4 — Swift: the same pipelines on iOS. The app and its Notification
// Service Extension both call `receive()`; the core's `BEGIN IMMEDIATE`
// transaction and its `processed` table make that safe (Listing 29.11 runs
// exactly this race).
import Foundation
import MurmurCore

actor MessagePipeline {
    private let core: MurmurCore
    private let api: MurmurAPIClient
    private let events: ConversationEvents

    init(core: MurmurCore, api: MurmurAPIClient, events: ConversationEvents) {
        self.core = core; self.api = api; self.events = events
    }

    func send(to account: String, content: Data) async throws {
        guard core.trust(account: account) != .changedFromVerified else {
            await events.blockedByKeyChange(account); return
        }
        // encrypt + outbox: COMMIT
        try core.enqueueOutgoing(account: account, content: content)
        try await flushOutbox()
    }

    func flushOutbox() async throws {
        for row in try core.pendingOutbox() {
            var envelopes = row.envelopes
            var sealed = row.sealed
            attempts: for _ in 0..<3 {
                let body = Self.body(row.account, envelopes)
                // sealed: no Authorization, no DPoP — the relay must not learn
                // the sender
                let (data, resp) = sealed
                    ? try await api.sendSealed(token: row.deliveryToken,
                        body: body)
                    : try await api.call("POST", "/v1/messages", body: body)
                switch resp.statusCode {
                case 202: try core.outboxDelivered(id: row.id); break attempts
                case 409 where String(decoding: data,
                    as: UTF8.self).contains("DEVICE_MISMATCH"):
                    envelopes = try core.repairFanout(id: row.id,
                        signedList: try await api.deviceList(row.account))
                case 401 where sealed: try core.outboxUseIdentifiedRoute(
                    id: row.id); sealed = false
                // retried by the next flush (launch, push, BGTask)
                default: break attempts
                }
            }
        }
    }

    /// `budget` limits work in the NSE (time and memory); the app passes nil.
    func receive(budget: Int? = nil) async throws -> [Decrypted] {
        let batch = try await api.fetchMessages(limit: budget ?? 100)
        var acked: [Data] = [], out: [Decrypted] = []
        for env in batch {
            do {
                // dedupe + decrypt + persist, one transaction
                let r = try core.decrypt(envelope: env.body)
                out.append(r); acked.append(env.guid)
            } catch CoreError.Storage {
                // e.g. locked before first unlock: ack nothing more
                break
            }
        }
        if !acked.isEmpty { try await api.ack(acked) }    // after the commits
        return out
    }

    static func body(_ account: String, _ envs: [String: Data]) -> Data {
        try! JSONSerialization.data(withJSONObject: [
            "recipient_account": account,
            "envelopes": envs.map { ["device": $0.key,
            "body": $0.value.base64EncodedString()] }])
    }
}
