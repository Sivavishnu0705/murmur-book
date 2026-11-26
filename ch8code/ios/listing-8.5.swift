import CryptoKit
import Foundation
import Security

struct MurmurPins {
    let host: String
    let pins: Set<String>                 // base64(SHA-256(SPKI DER))
    let report: (_ host: String, _ chainPins: [String]) -> Void

    /// SPKI DER for P-256 and RSA keys: SecKeyCopyExternalRepresentation returns the raw key,
    /// so the algorithm header must be prepended to rebuild the SubjectPublicKeyInfo.
    static func spkiSHA256(_ cert: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(cert),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attrs[kSecAttrKeyType] as? String,
              let bits = attrs[kSecAttrKeySizeInBits] as? Int,
              let header = spkiHeader(type: type, bits: bits) else { return nil }
        return Data(SHA256.hash(data: header + raw)).base64EncodedString()
    }

    private static let ecType = kSecAttrKeyTypeECSECPrimeRandom as String, rsaType = kSecAttrKeyTypeRSA as String

    private static func spkiHeader(type: String, bits: Int) -> Data? {
        switch (type, bits) {
        case (ecType, 256):   // id-ecPublicKey, prime256v1
            return Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                         0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                         0x42, 0x00])
        case (rsaType, 2048):               // rsaEncryption, 2048-bit
            return Data([0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                         0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00])
        default:
            return nil   // unknown key type: cannot pin → caller fails closed
        }
    }

    /// 1. platform evaluation with hostname policy; 2. pins over the VALIDATED chain.
    func evaluate(_ trust: SecTrust) -> Bool {
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else { return false }      // fail closed
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else { return false }
        let chainPins = chain.compactMap(Self.spkiSHA256)
        if chainPins.contains(where: pins.contains) { return true }
        report(host, chainPins)                                                     // never blocks
        return false
    }
}

final class PinningDelegate: NSObject, URLSessionDelegate {
    let pinsByHost: [String: MurmurPins]
    init(_ pins: [MurmurPins]) { pinsByHost = Dictionary(uniqueKeysWithValues: pins.map { ($0.host, $0) }) }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        guard let pins = pinsByHost[challenge.protectionSpace.host] else {
            completionHandler(.performDefaultHandling, nil); return   // unpinned host: system default
        }
        pins.evaluate(trust)
            ? completionHandler(.useCredential, URLCredential(trust: trust))
            : completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
