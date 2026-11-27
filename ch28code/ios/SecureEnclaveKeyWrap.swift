// SecureEnclaveKeyWrap.swift
// Listing 28.5 — Swift: the iOS PlatformKeyWrap — a Secure Enclave P-256 key
// that wraps the software X25519/Ed25519 keys with ECIES (ephemeral ECDH +
// X9.63 KDF + AES-GCM). The SE cannot hold Curve25519 keys, but it can make
// them useless off this device.
import CryptoKit
import Foundation
import MurmurCore      // UniFFI-generated: PlatformKeyWrap, CoreError
import Security

final class SecureEnclaveKeyWrap: PlatformKeyWrap {
    private static let tag = Data("example.murmur.wrap".utf8)
    private let algorithm =
        SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    private func privateKey() throws -> SecKey {
        let query: [CFString: Any] = [kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Self.tag,
            kSecAttrAccessGroup: MurmurKeychain.accessGroup,
            kSecReturnRef: true]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary,
            &item) == errSecSuccess { return (item as! SecKey) }
        var err: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage, &err)!
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: Self.tag,
            kSecAttrAccessGroup: MurmurKeychain.accessGroup,
            kSecAttrAccessControl: access]]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary,
            &err) else { throw CoreError.KeyUnavailable }
        return key
    }

    // Security.framework's ECIES takes no associated data, so the label is
    // bound by putting SHA-256(label) in front of the secret and checking it on
    // unwrap.
    func wrap(label: String, secret: Data) throws -> Data {
        let pub = SecKeyCopyPublicKey(try privateKey())!
        let pt = Data(SHA256.hash(data: Data(label.utf8))) + secret
        var err: Unmanaged<CFError>?
        guard let ct = SecKeyCreateEncryptedData(pub, algorithm, pt as CFData,
            &err) as Data? else { throw CoreError.KeyUnavailable }
        return ct
    }

    func unwrap(label: String, blob: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let pt = SecKeyCreateDecryptedData(try privateKey(), algorithm,
            blob as CFData, &err) as Data?,
              pt.count > 32,
                  pt.prefix(32) == Data(SHA256.hash(data: Data(label.utf8)))
        else { throw CoreError.KeyUnavailable }
        return pt.dropFirst(32)
    }

    /// Remote wipe and logout: delete the SE key; every blob it wrapped is now
    /// noise.
    static func destroy() {
        SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag,
                       kSecAttrAccessGroup: MurmurKeychain
                       .accessGroup] as CFDictionary)
    }
}
