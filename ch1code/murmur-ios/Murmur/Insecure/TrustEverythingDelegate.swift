// murmur-ios/Murmur/Insecure/TrustEverythingDelegate.swift
// ⚠️ INSECURE — FOR ILLUSTRATION ONLY. Never ship this code.

import Foundation

final class TrustEverythingDelegate: NSObject, URLSessionDelegate {

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition,
        URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // (1) No call to SecTrustEvaluateWithError. No hostname policy.
        // (2) Tells URLSession "I have decided this server is trusted."
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

// Usage:
let insecureSession = URLSession(
    configuration: .default,
    delegate: TrustEverythingDelegate(),  // (3)
    delegateQueue: nil
)
