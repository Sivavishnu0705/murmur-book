// oidc.go
// Listing 27.1 — Go: murmur-auth's configuration as an OIDC RELYING PARTY of upstream identity
// providers (Ch 12). Users may sign in with Google or Apple; murmur-auth validates their ID
// token, maps (iss, sub) to a Murmur account, and then issues ITS OWN DPoP-bound tokens.
// Upstream tokens never reach murmur-api, and upstream email addresses are not identities.
package main

import "time"

type UpstreamIdP struct {
       Issuer       string   // exact match against the ID token's iss
       DiscoveryURL string   // fetched at startup and cached; JWKS refreshed on unknown kid
       ClientID     string   // our client_id there = the expected aud of its ID tokens
       RedirectURI  string   // https://auth.murmur.example/callback/<idp>: claimed, exact match
       Scopes       []string // openid only, plus email for display; never more than needed
       Algs         []string // allowlist for ID token signatures
       MaxAge       time.Duration
       // EmailTrusted is true only where the provider is authoritative for the domain (Ch 12 §12.5);
       // even then email is used to SUGGEST linking, never to merge accounts silently.
       EmailTrusted func(domain string) bool
}

var upstreams = []UpstreamIdP{
       {Issuer: "https://accounts.google.com", DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
              ClientID: "murmur-auth.apps.googleusercontent.com", RedirectURI: "https://auth.murmur.example/callback/google",
              Scopes: []string{"openid", "email"}, Algs: []string{"RS256"}, MaxAge: 24 * time.Hour,
              EmailTrusted: func(d string) bool { return d == "gmail.com" }},
       {Issuer: "https://appleid.apple.com", DiscoveryURL: "https://appleid.apple.com/.well-known/openid-configuration",
              ClientID: "example.murmur.signin", RedirectURI: "https://auth.murmur.example/callback/apple",
              Scopes: []string{"openid", "email"}, Algs: []string{"RS256"}, MaxAge: 24 * time.Hour,
              EmailTrusted: func(string) bool { return false }}, // relay addresses; email_verified may be a string
}

// Every upstream login also requires: PKCE S256, state bound to the browser session, nonce
// (SHA-256 of it for Apple), and checks of iss, aud, azp, exp, iat, nonce, and auth_time where
// max_age was sent. The resulting Murmur session still needs a passkey for acr=phr (Ch 14).
