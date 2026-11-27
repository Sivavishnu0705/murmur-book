import CryptoKit
import Foundation
import Security

extension Data {
    var b64url: String { base64EncodedString().replacingOccurrences(of: "+",
        with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=",
        with: "") }
}

/// The device's first hardware-bound key. The Secure Enclave generates and
/// keeps the private key; we persist only its encrypted handle, in the shared
/// Keychain group so the NSE can sign too.
final class DPoPKey {
    private let key: SecureEnclave.P256.Signing.PrivateKey
    private static let account = "murmur-dpop-v1"

    init(keychain: KeychainStore) throws {
        // e.g. simulator
        guard SecureEnclave.isAvailable else { throw DPoPError.noSecureEnclave }
        if let blob = try keychain.read(Self.account) {
            key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob)
        } else {
            var err: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(nil,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    .privateKeyUsage, &err)
            else { throw err!.takeRetainedValue() as Error }
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
            // handle only; useless elsewhere
            try keychain.write(Self.account, key.dataRepresentation)
        }
    }

    var jwk: [String: String] {
        // 0x04 ‖ X(32) ‖ Y(32)
        let raw = key.publicKey.x963Representation
        return ["kty": "EC", "crv": "P-256",
                "x": raw[1..<33].b64url, "y": raw[33..<65].b64url]
    }

    // RFC 7638, for dpop_jkt
    var thumbprint: String {
        let j = jwk
        let canon = #"{"crv":"P-256","kty":"EC","x":"\#(j["x"]!)","y":"\#(
            j["y"]!)"}"#
        return Data(SHA256.hash(data: Data(canon.utf8))).b64url
    }

    func proof(method: String, url: URL, accessToken: String?,
        nonce: String?) throws -> String {
        var c = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        // htu: no query or fragment
        c.query = nil; c.fragment = nil
        var claims: [String: Any] = [
            "jti": Data((0..<16).map { _ in UInt8.random(in: 0...255) }).b64url,
            "htm": method, "htu": c.url!.absoluteString,
            "iat": Int(Date().timeIntervalSince1970)]
        if let at = accessToken { claims["ath"] = Data(SHA256.hash(data: Data(
            at.utf8))).b64url }
        if let nonce { claims["nonce"] = nonce }
        let header: [String: Any] = ["typ": "dpop+jwt", "alg": "ES256",
            "jwk": jwk]
        let input = try JSONSerialization.data(
            withJSONObject: header).b64url + "." +
                    JSONSerialization.data(withJSONObject: claims).b64url
        // SHA-256 inside the SE
        let sig = try key.signature(for: Data(input.utf8))
        // already raw r‖s: no DER
        return input + "." + sig.rawRepresentation.b64url
    }
}

enum DPoPError: Error { case noSecureEnclave }

/// URLSession wrapper: every call gets a fresh proof; a use_dpop_nonce
/// challenge is retried once.
actor DPoPClient {
    // configured with Murmur's pinning delegate (Ch 8)
    private let session: URLSession
    private let key: DPoPKey
    private let accessToken: () async throws -> String
    private var nonce: String?
    init(session: URLSession, key: DPoPKey,
        accessToken: @escaping () async throws -> String) {
        self.session = session; self.key = key; self.accessToken = accessToken
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var (data, resp) = try await send(request)
        if resp.statusCode == 401,
           (resp.value(forHTTPHeaderField: "WWW-Authenticate") ?? "").contains(
               "use_dpop_nonce") {
            // nonce was updated by send
            (data, resp) = try await send(request)
        }
        return (data, resp)
    }

    private func send(_ original: URLRequest) async throws -> (Data,
        HTTPURLResponse) {
        var req = original
        let at = try await accessToken()
        req.setValue("DPoP \(at)", forHTTPHeaderField: "Authorization")
        req.setValue(try key.proof(method: req.httpMethod ?? "GET",
            url: req.url!,
            accessToken: at, nonce: nonce), forHTTPHeaderField: "DPoP")
        let (data, r) = try await session.data(for: req)
        let resp = r as! HTTPURLResponse
        if let n = resp.value(forHTTPHeaderField: "DPoP-Nonce") { nonce = n }
        return (data, resp)
    }
}
