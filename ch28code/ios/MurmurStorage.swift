// MurmurStorage.swift
// Listing 28.7 — Swift: the iOS storage stack — a random SQLCipher key (and salt) as a Keychain
// item in the shared access group, AfterFirstUnlockThisDeviceOnly; a GRDB DatabasePool on
// SQLCipher in the App Group container; CompleteUntilFirstUserAuthentication on the database,
// WAL and SHM files; backup exclusion; and the wipe: key first, then files.
import Foundation
import GRDB          // built with SQLCipher (GRDB's SQLCipher integration)
import Security

enum DatabaseKey {
    private static let service = "example.murmur.db-key"

    /// 32-byte key ‖ 16-byte salt, created once. The salt is kept OUT of the file because the file
    /// header is plaintext (see `prepare` below), and SQLCipher normally stores the salt there.
    static func load() throws -> Data {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                      kSecAttrAccessGroup: MurmurKeychain.accessGroup, kSecReturnData: true]
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess: return item as! Data
        case errSecItemNotFound: break
        case let status: throw StorageError.keychain(status)   // e.g. errSecInteractionNotAllowed before first unlock
        }
        var key = Data(count: 48)
        guard key.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 48, $0.baseAddress!) }) == errSecSuccess
        else { throw StorageError.random }
        let add: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                    kSecAttrAccessGroup: MurmurKeychain.accessGroup, kSecValueData: key,
                                    kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                    kSecAttrSynchronizable: false]                 // never in iCloud Keychain
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw StorageError.keychain(status) }
        return key
    }

    static func delete() {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                       kSecAttrAccessGroup: MurmurKeychain.accessGroup] as CFDictionary)
    }
}

enum MurmurStorage {
    static let appGroup = "group.example.murmur"
    static let protection = FileProtectionType.completeUntilFirstUserAuthentication

    static var directory: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)!
            .appendingPathComponent("Murmur", isDirectory: true)
    }

    static func open() throws -> DatabasePool {
        var dir = directory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.protectionKey: protection])
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true        // iCloud and Finder backups
        try dir.setResourceValues(rv)

        let keyAndSalt = try DatabaseKey.load()
        var config = Configuration()
        config.observesSuspensionNotifications = true   // release file locks when suspended (0xdead10cc)
        config.prepareDatabase { db in
            // Raw key ‖ explicit salt (96 hex digits): no PBKDF2, salt supplied from the Keychain.
            try db.usePassphrase("x'\(keyAndSalt.hex)'")
            // A 32-byte plaintext header lets iOS recognize the file as SQLite, so the app and its
            // NSE can hold WAL locks in the shared container without being killed on suspension.
            // The header holds only SQLite format fields; no keys, no salt, no data.
            try db.execute(sql: "PRAGMA cipher_plaintext_header_size = 32")
        }
        let dbURL = dir.appendingPathComponent("app.db")
        let pool = try DatabasePool(path: dbURL.path, configuration: config)   // WAL mode
        // The -wal and -shm files exist now; give all three the same protection class.
        for suffix in ["", "-wal", "-shm"] {
            let path = dbURL.path + suffix
            if FileManager.default.fileExists(atPath: path) {
                try FileManager.default.setAttributes([.protectionKey: protection], ofItemAtPath: path)
            }
        }
        return pool
    }

    /// Logout and remote revocation: the Keychain item and the SE wrap key first, then the files.
    static func wipe(_ pool: DatabasePool?) {
        try? pool?.close()
        DatabaseKey.delete()
        SecureEnclaveKeyWrap.destroy()
        SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: DeviceEnrollment.dpopTag,
                       kSecAttrAccessGroup: MurmurKeychain.accessGroup] as CFDictionary)
        try? FileManager.default.removeItem(at: directory)
    }
}

enum StorageError: Error { case keychain(OSStatus), random }

extension Data { var hex: String { map { String(format: "%02x", $0) }.joined() } }
