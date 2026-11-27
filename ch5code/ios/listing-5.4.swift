import Foundation
import Security

enum MurmurTrust {
    /// Public endpoints (api.murmur.example): system trust store + hostname,
    /// then an ADDITIONAL check. Chapter 8 adds SPKI pinning in the same place.
    static func evaluatePublic(_ trust: SecTrust, host: String) -> Bool {
        // server auth + hostname
        let policy = SecPolicyCreateSSL(true, host as CFString)
        guard SecTrustSetPolicies(trust,
            policy) == errSecSuccess else { return false }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            print(
                "Murmur trust: rejected: " +
                "\(error.map(String.init(describing:)) ?? "-")")
            return false
        }
        // Added check: require that Certificate Transparency was verified. A
        // chain to a user- or MDM-installed root (e.g. a TLS inspection proxy)
        // is not CT-qualified, so this rejects it even though the system
        // evaluation accepted it.
        let result = SecTrustCopyResult(trust) as? [String: Any]
        return (result?[
            kSecTrustCertificateTransparency as String] as? Bool) == true
    }

    /// Private endpoints (enroll.murmur.example, Chapter 9): ONLY Murmur's
    /// bundled root is an anchor — no system roots, no user-installed roots.
    static func evaluatePrivate(_ trust: SecTrust, host: String,
                                murmurRoot: SecCertificate) -> Bool {
        let policy = SecPolicyCreateSSL(true, host as CFString)
        guard SecTrustSetPolicies(trust, policy) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust,
                  [murmurRoot] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
        else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}

final class MurmurSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (
                    URLSession.AuthChallengeDisposition,
                    URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        if MurmurTrust.evaluatePublic(trust,
            host: challenge.protectionSpace.host) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            // fail closed
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
