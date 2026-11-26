import AuthenticationServices

@MainActor
final class MurmurPasskeys: NSObject, ASAuthorizationControllerDelegate,
                            ASAuthorizationControllerPresentationContextProviding {
    private let api: MurmurAuthAPI
    private let anchor: ASPresentationAnchor
    private let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: "murmur.example")            // must match webcredentials:murmur.example
    private var continuation: CheckedContinuation<ASAuthorization, Error>?
    init(api: MurmurAuthAPI, anchor: ASPresentationAnchor) { self.api = api; self.anchor = anchor }

    func register() async throws {
        let o = try await api.passkeyRegistrationOptions()   // challenge, user handle, name
        let req = provider.createCredentialRegistrationRequest(
            challenge: o.challenge, name: o.userName, userID: o.userHandle)
        req.userVerificationPreference = .required
        guard let reg = try await perform([req]).credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
              let att = reg.rawAttestationObject else { throw URLError(.badServerResponse) }
        try await api.finishPasskeyRegistration(id: reg.credentialID,
            clientDataJSON: reg.rawClientDataJSON, attestationObject: att)
    }

    func assert(preferImmediatelyAvailable: Bool = false) async throws -> PasskeyAssertion {
        let o = try await api.passkeyAssertionOptions()
        let req = provider.createCredentialAssertionRequest(challenge: o.challenge)
        req.userVerificationPreference = .required
        let a = try await perform([req], immediate: preferImmediatelyAvailable).credential
            as! ASAuthorizationPlatformPublicKeyCredentialAssertion
        return PasskeyAssertion(id: a.credentialID, clientDataJSON: a.rawClientDataJSON,
            authenticatorData: a.rawAuthenticatorData, signature: a.signature, userHandle: a.userID)
    }

    private func perform(_ reqs: [ASAuthorizationRequest], immediate: Bool = false) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { c in
            continuation = c
            let ctl = ASAuthorizationController(authorizationRequests: reqs)
            ctl.delegate = self; ctl.presentationContextProvider = self
            if immediate { ctl.performRequests(options: .preferImmediatelyAvailableCredentials) }
            else { ctl.performRequests() }
        }
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization a: ASAuthorization) {
        continuation?.resume(returning: a); continuation = nil
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError e: Error) {
        continuation?.resume(throwing: e); continuation = nil   // .canceled, or .failed (association?)
    }
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }
}
