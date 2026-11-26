// passkeys.go — murmur-auth's passkey endpoints with github.com/go-webauthn/webauthn.
// Checked against go-webauthn v0.15.0 (the newest release that supports Go 1.24). Account (which
// implements webauthn.User), AccountDB and ErrConfirmFromAnotherDevice are murmur-auth's own types.
package passkeys

import (
       "net/http"

       "github.com/go-webauthn/webauthn/protocol"
       "github.com/go-webauthn/webauthn/webauthn"
)

func NewRP() (*webauthn.WebAuthn, error) {
       return webauthn.New(&webauthn.Config{
              RPID:          "murmur.example", // the registrable domain: works for auth. and both apps
              RPDisplayName: "Murmur",
              RPOrigins: []string{ // EXPLICIT allowlist: this is the anti-phishing check
                     "https://auth.murmur.example", // web login in the external user-agent
                     "https://murmur.example",      // iOS app (associated domain)
                     "android:apk-key-hash:FyNmShqTj3BpxuPLPqLQtB_4f8DeNAw7Rk3wFt8n0Hw", // release signing key
              },
       })
}

// Registration step 1: options for navigator.credentials.create / Credential Manager / ASAuthorization.
func BeginRegistration(w *webauthn.WebAuthn, u *Account) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
       return w.BeginRegistration(u, // u implements webauthn.User: WebAuthnID() = random user handle
              webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
                     ResidentKey:      protocol.ResidentKeyRequirementRequired, // discoverable: a passkey
                     UserVerification: protocol.VerificationRequired,           // biometric/PIN, sets UV
              }),
              webauthn.WithConveyancePreference(protocol.PreferNoAttestation), // §14.2: no attestation
              webauthn.WithExclusions(webauthn.Credentials(u.WebAuthnCredentials()).CredentialDescriptors()), // no duplicates
       )
       // Store SessionData (contains the challenge) server-side, keyed to this ceremony, 5-minute TTL.
}

// Registration step 2: verifies type, challenge, origin, rpIdHash, flags, attestation, key.
func FinishRegistration(w *webauthn.WebAuthn, u *Account, s webauthn.SessionData, r *http.Request) error {
       cred, err := w.FinishRegistration(u, s, r)
       if err != nil {
              return err // never "try again with relaxed settings"
       }
       // Persist: cred.ID, cred.PublicKey, cred.Authenticator.SignCount, cred.Flags.BackupEligible,
       // cred.Flags.BackupState, cred.Transport, cred.Authenticator.AAGUID; plus a display name.
       // Then: notify the user's other devices "a passkey was added" (Ch 15).
       return u.SaveCredential(cred)
}

// Authentication with discoverable credentials (no username typed).
func BeginLogin(w *webauthn.WebAuthn) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
       return w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
}

func FinishLogin(w *webauthn.WebAuthn, s webauthn.SessionData, r *http.Request, db AccountDB) (*Account, error) {
       var acct *Account
       cred, err := w.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
              a, err := db.ByUserHandle(userHandle) // the handle names the account; rawID the credential
              acct = a
              return a, err
       }, s, r)
       if err != nil {
              return nil, err // bad challenge/origin/rpIdHash/flags/signature: all fail here
       }
       if cred.Authenticator.CloneWarning { // non-zero counter failed to increase (§14.5)
              db.RecordSecurityEvent(acct, "passkey counter regression")
              return nil, ErrConfirmFromAnotherDevice
       }
       // Persist the new counter and BS flag; record last use; then issue the OIDC session with
       // amr/acr reflecting a phishing-resistant authenticator with user verification (§14.6).
       return acct, db.UpdateCredential(acct, cred)
}
