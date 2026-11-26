// DeviceEnrollment.swift
// Listing 28.2 — Swift: device enrollment on iOS — a Secure Enclave P-256 DPoP key in the SHARED
// Keychain access group (the Notification Service Extension signs DPoP proofs for its fetch),
// an App Attest attestation over SHA-256(nonce ‖ SPKI), and the proof of possession.
import CryptoKit
import DeviceCheck
import Foundation
import Security

enum MurmurKeychain {
    static let accessGroup = "TEAMID1234.example.murmur.shared"   // app + NSE entitlement
}

struct DeviceEnrollment {
    static let dpopTag = Data("example.murmur.dpop".utf8)

    /// 1. DPoP key: Secure Enclave, non-exportable, usable after first unlock (so the NSE can
    ///    sign while the phone is locked), never synced, never in backups.
    static func createDpopKey() throws -> SecKey {
        SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: dpopTag,
                       kSecAttrAccessGroup: MurmurKeychain.accessGroup] as CFDictionary)
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           .privateKeyUsage, &err) else { throw err!.takeRetainedValue() }
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: dpopTag,
                                  kSecAttrAccessGroup: MurmurKeychain.accessGroup, kSecAttrAccessControl: access]]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else { throw err!.takeRetainedValue() }
        return key
    }

    /// 2. App Attest: proves a genuine Murmur app on a genuine device asked to enroll THIS key
    ///    with THIS nonce. It does not prove the DPoP key is in the Secure Enclave (Ch 9 §9.6).
    static func attest(nonce: Data, spki: Data) async throws -> (keyId: String, attestation: Data) {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw EnrollError.attestationUnsupported }  // policy decides (Ch 9)
        let keyId = try await service.generateKey()
        let clientDataHash = Data(SHA256.hash(data: nonce + spki))
        return (keyId, try await service.attestKey(keyId, clientDataHash: clientDataHash))
    }

    /// 3. Proof of possession over "murmur/v1/enroll-pop\0" ‖ nonce ‖ account.
    static func proofOfPossession(_ key: SecKey, nonce: Data, account: String) throws -> Data {
        var err: Unmanaged<CFError>?
        let msg = Data("murmur/v1/enroll-pop\u{0}".utf8) + nonce + Data(account.utf8)
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, msg as CFData, &err) as Data?
        else { throw err!.takeRetainedValue() }
        return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation   // r‖s
    }

    /// SubjectPublicKeyInfo of the DPoP key (what the attestation and the server hash).
    static func spki(_ key: SecKey) throws -> Data {
        let pub = SecKeyCopyPublicKey(key)!
        var err: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(pub, &err) as Data? else { throw err!.takeRetainedValue() }
        return try P256.Signing.PublicKey(x963Representation: x963).derRepresentation
    }
}

enum EnrollError: Error { case attestationUnsupported }
