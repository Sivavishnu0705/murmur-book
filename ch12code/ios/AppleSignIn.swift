// AppleSignIn.swift — Sign in with Apple, backend-issued nonce sent hashed to Apple.
import AuthenticationServices
import CryptoKit

@MainActor
final class AppleSignIn: NSObject, ASAuthorizationControllerDelegate,
                         ASAuthorizationControllerPresentationContextProviding {
    private let auth: MurmurAuthAPI
    private let anchor: ASPresentationAnchor
    private var continuation: CheckedContinuation<ASAuthorizationAppleIDCredential, Error>?
    init(auth: MurmurAuthAPI, anchor: ASPresentationAnchor) { self.auth = auth; self.anchor = anchor }

    func signIn() async throws -> MurmurTokens {
        let nonce = try await auth.newLoginNonce()                       // ① from murmur-auth
        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.email]                               // name/email arrive ONCE
        request.nonce = SHA256.hash(data: Data(nonce.utf8))              // ② Apple receives the hash
            .map { String(format: "%02x", $0) }.joined()
        let cred: ASAuthorizationAppleIDCredential = try await withCheckedThrowingContinuation { c in
            continuation = c
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
        guard let data = cred.identityToken, let idToken = String(data: data, encoding: .utf8) else {
            throw URLError(.userAuthenticationRequired)
        }
        // ③ Raw nonce + token to the backend, which hashes the nonce and compares (Listing 12.1).
        return try await auth.federate(provider: "apple", idToken: idToken, nonce: nonce,
                                       firstTimeEmail: cred.email)       // store on first sign-in only
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization a: ASAuthorization) {
        if let c = a.credential as? ASAuthorizationAppleIDCredential { continuation?.resume(returning: c) }
        else { continuation?.resume(throwing: URLError(.badServerResponse)) }
        continuation = nil
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError e: Error) {
        continuation?.resume(throwing: e); continuation = nil
    }
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }
}
