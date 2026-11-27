// MurmurAPIClient.swift
// Listing 28.13 — Swift: DPoP-enabled API client on URLSession. The pinning
// delegate is Listing 8.5 (SPKI pins layered on default evaluation). A fresh
// DPoP proof per attempt; one Idempotency-Key per state-changing request,
// reused by every retry.
import CryptoKit
import Foundation
import Security

actor MurmurAPIClient {
    private let origin = URL(string: "https://api.murmur.example")!
    private let session: URLSession
    private let tokens: TokenProvider
    private var dpopNonce: String?

    init(tokens: TokenProvider, pinning: URLSessionDelegate) {
        // no shared cookie or cache storage
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.waitsForConnectivity = false
        session = URLSession(configuration: cfg, delegate: pinning,
            delegateQueue: nil)
        self.tokens = tokens
    }

    private func dpopKey() throws -> SecKey {
        let q: [CFString: Any] = [kSecClass: kSecClassKey,
            kSecAttrApplicationTag: DeviceEnrollment.dpopTag,
            kSecAttrAccessGroup: MurmurKeychain.accessGroup,
            kSecReturnRef: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary,
            &item) == errSecSuccess else { throw APIError.noDeviceKey }
        return item as! SecKey
    }

    private func proof(method: String, path: String,
        accessToken: String) throws -> String {
        let key = try dpopKey()
        // 04 ‖ X ‖ Y
        let x963 = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!,
            nil)! as Data
        let jwk = ["kty": "EC", "crv": "P-256", "x": x963[1...32].b64url,
            "y": x963[33...64].b64url]
        var claims: [String: Any] = ["jti": UUID().uuidString, "htm": method,
            "htu": origin.absoluteString + path,
            "iat": Int(Date().timeIntervalSince1970),
            "ath": Data(SHA256.hash(data: Data(accessToken.utf8))).b64url]
        if let n = dpopNonce { claims["nonce"] = n }
        let h = try JSONSerialization.data(withJSONObject: ["typ": "dpop+jwt",
            "alg": "ES256", "jwk": jwk] as [String: Any])
        let c = try JSONSerialization.data(withJSONObject: claims)
        let input = h.b64url + "." + c.b64url
        var err: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(key,
            .ecdsaSignatureMessageX962SHA256, Data(input.utf8) as CFData,
            &err) as Data?
        else { throw err!.takeRetainedValue() }
        return input + "." + (try P256.Signing.ECDSASignature(
            derRepresentation: der).rawRepresentation).b64url
    }

    func call(_ method: String, _ path: String,
        body: Data? = nil) async throws -> (Data, HTTPURLResponse) {
        let idempotencyKey = (
            method == "POST" || method == "PUT") ? UUID().uuidString : nil
        var refreshed = false, nonceRetried = false
        for attempt in 0..<4 {
            let at = try await tokens.accessToken()
            var req = URLRequest(url: origin.appendingPathComponent(path))
            req.httpMethod = method
            req.httpBody = body
            req.setValue("DPoP \(at)", forHTTPHeaderField: "Authorization")
            req.setValue(try proof(method: method, path: path, accessToken: at),
                forHTTPHeaderField: "DPoP")
            if let k = idempotencyKey { req.setValue(k,
                forHTTPHeaderField: "Idempotency-Key") }
            let result: (Data, URLResponse)
            do {
                result = try await session.data(for: req)
            } catch where (
                error as? URLError)?.code != .cancelled && attempt < 3 {
                // same key: safe
                try await Task.sleep(nanoseconds: UInt64(
                    500_000_000) << attempt)
                continue
            }
            let data = result.0
            guard let resp = result.1 as? HTTPURLResponse else {
                throw APIError.gaveUp }
            if let n = resp.value(forHTTPHeaderField: "DPoP-Nonce") {
                dpopNonce = n }
            let challenge = resp.value(
                forHTTPHeaderField: "WWW-Authenticate") ?? ""
            switch resp.statusCode {
            case 401 where challenge.contains(
                "use_dpop_nonce") && !nonceRetried: nonceRetried = true
            case 401 where challenge.contains("invalid_token") && !refreshed:
                // single-flight (Listing 11.4)
                refreshed = true; try await tokens.refresh()
            case let code where [429, 502, 503,
                504].contains(code) && attempt < 3:
                let wait = Double(resp.value(
                    forHTTPHeaderField: "Retry-After") ?? "") ?? 0.5 * pow(2,
                    Double(attempt))
                try await Task.sleep(nanoseconds: UInt64(wait * 1e9))
            // success, step-up challenge (the UI handles it), or final
            default: return (data, resp)
            }
        }
        throw APIError.gaveUp
    }
}

protocol TokenProvider: Sendable { func accessToken() async throws -> String;
    func refresh() async throws }
// staleEpoch: a DS commit lost the race (Ch 30)
enum APIError: Error { case noDeviceKey, gaveUp, staleEpoch }
extension Data { var b64url: String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=",
    with: "") } }
