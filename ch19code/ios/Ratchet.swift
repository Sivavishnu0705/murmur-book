// Ratchet.swift — the KDFs and message encryption in CryptoKit (matching Listing 19.1), and the
// persistence layer shared by the app and the Notification Service Extension.
import CryptoKit
import Foundation
import GRDB          // built against SQLCipher

enum DR {
    static let infoRK = Data("Murmur_DR_Root_v1".utf8), infoMsg = Data("Murmur_DR_Msg_v1".utf8)

    static func kdfRK(_ rk: SymmetricKey, _ dhOut: SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let out = dhOut.hkdfDerivedSymmetricKey(using: SHA256.self, salt: rk.withUnsafeBytes { Data($0) },
                                                sharedInfo: infoRK, outputByteCount: 64)
        let b = out.withUnsafeBytes { Data($0) }
        return (SymmetricKey(data: b.prefix(32)), SymmetricKey(data: b.suffix(32)))
    }
    static func kdfCK(_ ck: SymmetricKey) -> (next: SymmetricKey, mk: SymmetricKey) {
        (SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: ck))),
         SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: ck))))
    }
    static func seal(_ mk: SymmetricKey, _ pt: Data, ad: Data) throws -> Data {
        let kn = HKDF<SHA256>.deriveKey(inputKeyMaterial: mk, salt: Data(count: 32), info: infoMsg,
                                        outputByteCount: 44).withUnsafeBytes { Data($0) }
        let box = try AES.GCM.seal(pt, using: SymmetricKey(data: kn.prefix(32)),
                                   nonce: AES.GCM.Nonce(data: kn.suffix(12)), authenticating: ad)
        return box.ciphertext + box.tag
    }
}

final class RatchetStore {
    private let db: DatabaseQueue

    init(passphrase: Data) throws {
        let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.example.murmur")!
        var url = dir.appendingPathComponent("murmur.db")
        var config = Configuration()
        config.prepareDatabase { db in try db.usePassphrase(passphrase) }   // key from ThisDeviceOnly Keychain
        config.busyMode = .timeout(3)                                        // wait for the other process
        config.observesSuspensionNotifications = true                       // avoid 0xdead10cc
        db = try DatabaseQueue(path: url.path, configuration: config)
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try url.setResourceValues(rv)
    }

    /// Main app AND NSE call this. BEGIN IMMEDIATE takes SQLite's write lock before reading,
    /// so the two processes can never both advance the same session from the same state.
    func receive(peer: String, msgID: String, envelope: Data) throws -> Data? {
        try db.writeWithoutTransaction { db in
            var plaintext: Data?
            try db.inTransaction(.immediate) {
                guard let row = try Row.fetchOne(db, sql: "SELECT state FROM sessions WHERE peer = ?",
                                                 arguments: [peer]) else { return .rollback }
                guard let r = try? MurmurCore.ratchetDecrypt(state: row["state"], envelope: envelope) else {
                    return .rollback                                          // forged/duplicate: untouched
                }
                try db.execute(sql: "UPDATE sessions SET state = ? WHERE peer = ?", arguments: [r.newState, peer])
                try db.execute(sql: "INSERT INTO messages(id, peer, body) VALUES (?, ?, ?)",
                               arguments: [msgID, peer, r.plaintext])        // UNIQUE(id): dedupe
                plaintext = r.plaintext
                return .commit
            }
            return plaintext
        }
    }
}
