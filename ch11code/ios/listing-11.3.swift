import AuthenticationServices
import CryptoKit
import Foundation

enum PKCE {
    static func verifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        precondition(SecRandomCopyBytes(kSecRandomDefault, bytes.count,
            &bytes) == errSecSuccess)
        // 43 characters
        return Data(bytes).base64URL
    }
    static func challenge(_ verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URL
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/",
                with: "_").replacingOccurrences(of: "=", with: "")
    }
}

struct Tokens: Decodable { let access_token: String; let refresh_token: String;
    let expires_in: Int }
enum LoginError: Error { case cancelled, badState, badIssuer, noCode,
    tokenRequestFailed }

@MainActor
final class MurmurLogin: NSObject,
    ASWebAuthenticationPresentationContextProviding {
    let issuer = "https://auth.murmur.example"
    let clientID = "murmur-ios"
    private let window: ASPresentationAnchor
    init(window: ASPresentationAnchor) { self.window = window }
    func presentationAnchor(
        for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        window }

    func signIn() async throws -> Tokens {
        let verifier = PKCE.verifier()
        // any 256-bit random value
        let state = PKCE.verifier()
        let useHTTPS: Bool
        if #available(iOS 17.4, *) { useHTTPS = true } else { useHTTPS = false }
        let redirect = useHTTPS ? "https://app.murmur.example/oauth/callback"
                                // registered fallback
                                : "example.murmur:/oauth/callback"

        var c = URLComponents(string: "\(issuer)/authorize")!
        c.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: clientID),
            .init(name: "redirect_uri", value: redirect),
            .init(name: "scope",
            value: "openid messages:send messages:read contacts:read"),
            .init(name: "state", value: state),
            .init(name: "code_challenge", value: PKCE.challenge(verifier)),
            .init(name: "code_challenge_method", value: "S256"),
        ]

        let callback: URL = try await withCheckedThrowingContinuation { cont in
            let done: ASWebAuthenticationSession.CompletionHandler = { url,
                error in
                if let url { cont.resume(returning: url) } else { cont.resume(
                    throwing: error ?? LoginError.cancelled) }
            }
            let session: ASWebAuthenticationSession
            if #available(iOS 17.4, *) {
                session = ASWebAuthenticationSession(url: c.url!,
                    callback: .https(host: "app.murmur.example",
                    path: "/oauth/callback"),
                    // verified like a Universal Link
                    completionHandler: done)
            } else {
                session = ASWebAuthenticationSession(url: c.url!,
                    callbackURLScheme: "example.murmur",
                    completionHandler: done)
            }
            session.presentationContextProvider = self
            // Murmur's choice (Chapter 15 §15.1)
            session.prefersEphemeralWebBrowserSession = true
            if !session.start() { cont.resume(throwing: LoginError.cancelled) }
        }

        let items = URLComponents(url: callback,
            resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ n: String) -> String? { items.first {
            $0.name == n }?.value }
        // CSRF / injection
        guard value("state") == state else { throw LoginError.badState }
        // mix-up (RFC 9207)
        if let iss = value("iss"), iss != issuer { throw LoginError.badIssuer }
        guard let code = value("code") else { throw LoginError.noCode }

        // Back channel: token request (TLS pinned to murmur-auth, Chapter 8).
        var req = URLRequest(url: URL(string: "\(issuer)/token")!)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded",
            forHTTPHeaderField: "Content-Type")
        var form = URLComponents()
        form.queryItems = [.init(name: "grant_type",
            value: "authorization_code"),
            .init(name: "code", value: code), .init(name: "redirect_uri",
            value: redirect),
            .init(name: "client_id", value: clientID),
            .init(name: "code_verifier", value: verifier)]
        req.httpBody = form.percentEncodedQuery?.data(using: .utf8)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw LoginError.tokenRequestFailed }
        return try JSONDecoder().decode(Tokens.self, from: data)
    }
}
