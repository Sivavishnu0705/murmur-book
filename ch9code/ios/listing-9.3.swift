import CryptoKit
import DeviceCheck
import Foundation
import Security

enum DeviceMtls {
    static let tag = Data("example.murmur.device-mtls".utf8)

    /// 1. Persistent Secure Enclave P-256 key, so the keychain can pair it with
    /// a certificate.
    static func createKey() throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage,
            nil)!
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary,
            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    /// SubjectPublicKeyInfo DER of the P-256 public key (header from Chapter 8,
    /// Listing 8.5).
    static func spki(of key: SecKey) -> Data {
        let header = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00])
        let raw = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!,
            nil)! as Data
        return header + raw
    }

    /// 2. Proof of possession over SHA-256("murmur/v1/enroll-pop\0" ‖ nonce ‖
    /// account).
    static func proofOfPossession(_ key: SecKey, nonce: Data,
        account: String) throws -> Data {
        let digest = Data(SHA256.hash(data: Data(
            "murmur/v1/enroll-pop\u{0}".utf8) + nonce + Data(account.utf8)))
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return sig                                       // DER-encoded ECDSA
    }

    /// 3. App Attest: a SEPARATE Apple-attested key vouches that the genuine
    /// app, on a genuine device, requested a certificate for THIS mTLS public
    /// key with THIS nonce.
    static func appAttest(nonce: Data,
        mtlsSPKI: Data) async throws -> (keyId: Data, attestation: Data) {
        let service = DCAppAttestService.shared
        // e.g. simulator
        guard service.isSupported else { throw URLError(.unsupportedURL) }
        // base64 string
        let keyId = try await service.generateKey()
        let clientDataHash = Data(SHA256.hash(data: nonce + mtlsSPKI))
        let attestation = try await service.attestKey(keyId,
            clientDataHash: clientDataHash)
        return (Data(base64Encoded: keyId)!, attestation)
    }

    static let certLabel = "murmur-device-certificate"

    /// 4. Store the issued certificate; the keychain pairs it with the SE key →
    /// SecIdentity. Renewal issues a NEW certificate for the SAME key every few
    /// days, so first delete previously stored device certificates: otherwise
    /// the identity query below may match an expired certificate instead of the
    /// renewed one.
    static func storeAndLoadIdentity(
        certificateDER: Data) throws -> SecIdentity {
        let cert = SecCertificateCreateWithData(nil, certificateDER as CFData)!
        let old: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                  kSecAttrLabel as String: certLabel]
        let deleted = SecItemDelete(old as CFDictionary)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(deleted))
        }
        let add: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                  kSecValueRef as String: cert,
                                  kSecAttrLabel as String: certLabel]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                    kSecAttrApplicationTag as String: tag,
                                    kSecReturnRef as String: true]
        var item: CFTypeRef?
        let found = SecItemCopyMatching(query as CFDictionary, &item)
        guard found == errSecSuccess, let identity = item else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(found))
        }
        return identity as! SecIdentity
    }
}

/// 5. Present the identity when the server asks for a client certificate.
final class MtlsDelegate: NSObject, URLSessionDelegate {
    let identity: SecIdentity
    let devicesCA: SecCertificate       // intermediate to send with the leaf
    // private anchor for enroll.murmur.example
    let murmurRoot: SecCertificate
    init(identity: SecIdentity, devicesCA: SecCertificate,
        murmurRoot: SecCertificate) {
        self.identity = identity; self.devicesCA = devicesCA; self.murmurRoot =
            murmurRoot
    }

    func urlSession(_ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition,
        URLCredential?) -> Void) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodClientCertificate:
            completionHandler(.useCredential,
                              URLCredential(identity: identity,
                              certificates: [devicesCA],
                              persistence: .forSession))
        case NSURLAuthenticationMethodServerTrust:
            // Private endpoint: Murmur root as the ONLY anchor (Chapter 5,
            // Listing 5.4).
            guard let trust = challenge.protectionSpace.serverTrust,
                  MurmurTrust.evaluatePrivate(trust,
                      host: challenge.protectionSpace.host,
                      murmurRoot: murmurRoot) else {
                completionHandler(.cancelAuthenticationChallenge, nil); return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
