// AttachmentCrypto.swift
// Listing 29.6 — Swift: the same STREAM format with CryptoKit and fixed 64 KiB reads. Each
// chunk is processed inside an autorelease pool, so memory stays flat in the 24 MB NSE too.
import CryptoKit
import Foundation

enum AttachmentCrypto {
    static let buf = 64 * 1024, tag = 16

    static func nonce(_ prefix: Data, _ i: UInt32, _ last: Bool) throws -> AES.GCM.Nonce {
        var n = prefix
        withUnsafeBytes(of: i.bigEndian) { n.append(contentsOf: $0) }
        n.append(last ? 1 : 0)
        return try AES.GCM.Nonce(data: n)
    }

    static func encrypt(src: FileHandle, dst: FileHandle) throws -> (key: SymmetricKey, digest: Data, size: Int) {
        let key = SymmetricKey(size: .bits256)
        var prefix = Data(count: 7)
        _ = prefix.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 7, $0.baseAddress!) }
        var sha = SHA256(), size = 7
        try dst.write(contentsOf: prefix); sha.update(data: prefix)
        var cur = try src.read(upToCount: buf) ?? Data(), i: UInt32 = 0
        while true {
            let next = try src.read(upToCount: buf) ?? Data()
            let last = next.isEmpty
            try autoreleasepool {
                let box = try AES.GCM.seal(cur, using: key, nonce: try nonce(prefix, i, last))
                let out = box.ciphertext + box.tag
                try dst.write(contentsOf: out); sha.update(data: out); size += out.count
            }
            if last { break }
            cur = next; i += 1
        }
        return (key, Data(sha.finalize()), size)
    }

    /// Verify-before-release into `dst` via `dst.partial`; also usable from the NSE with a size cap.
    static func decrypt(src: FileHandle, key: SymmetricKey, dst: URL) throws {
        let tmp = dst.appendingPathExtension("partial")
        FileManager.default.createFile(atPath: tmp.path, contents: nil,
                                       attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        let out = try FileHandle(forWritingTo: tmp)
        do {
            guard let prefix = try src.read(upToCount: 7), prefix.count == 7 else { throw CryptoKitError.authenticationFailure }
            var cur = try src.read(upToCount: buf + tag) ?? Data(), i: UInt32 = 0
            while true {
                let next = try src.read(upToCount: buf + tag) ?? Data()
                let last = next.isEmpty
                guard cur.count >= tag else { throw CryptoKitError.authenticationFailure }
                try autoreleasepool {
                    let box = try AES.GCM.SealedBox(nonce: try nonce(prefix, i, last),
                                                    ciphertext: cur.dropLast(tag), tag: cur.suffix(tag))
                    try out.write(contentsOf: try AES.GCM.open(box, using: key))
                }
                if last { break }
                cur = next; i += 1
            }
            try out.close()
            _ = try FileManager.default.replaceItemAt(dst, withItemAt: tmp)   // release
        } catch {
            try? out.close(); try? FileManager.default.removeItem(at: tmp)
            throw error                                                       // nothing released
        }
    }
}
