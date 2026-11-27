// main.go
// Listing 12.4 — Go: lab driver. A test IdP (discovery + JWKS over TLS) issues
// ID tokens; the backend verifier (Listing 12.1) and account logic (Listing
// 12.2) are attacked.
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "time"
)

type idp struct {
    issuer string
    keys   map[string]*ecdsa.PrivateKey
    cur    string
}

func (p *idp) sign(kid string, claims map[string]any, alg string) string {
    h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid,
        "typ": "JWT"})
    c, _ := json.Marshal(claims)
    in := b64(h) + "." + b64(c)
    if alg == "none" {
        return in + "."
    }
    d := sha256.Sum256([]byte(in))
    r, s, _ := ecdsa.Sign(rand.Reader, p.keys[kid], d[:])
    sig := make([]byte, 64)
    r.FillBytes(sig[:32])
    s.FillBytes(sig[32:])
    return in + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newKey() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(),
    rand.Reader); return k }

func (p *idp) handler(advertisedIssuer *string) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/.well-known/openid-configuration",
        func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"issuer": *advertisedIssuer,
        "jwks_uri": p.issuer + "/jwks"})
    })
    mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
        var ks []map[string]string
        for kid, k := range p.keys {
            ks = append(ks, map[string]string{"kty": "EC", "crv": "P-256",
            "use": "sig", "kid": kid,
                "x": b64(k.X.FillBytes(make([]byte, 32))),
                "y": b64(k.Y.FillBytes(make([]byte, 32)))})
        }
        json.NewEncoder(w).Encode(map[string]any{"keys": ks})
    })
    return mux
}

func main() {
    real := &idp{keys: map[string]*ecdsa.PrivateKey{"k1": newKey()}, cur: "k1"}
    var adv string
    srv := httptest.NewTLSServer(real.handler(&adv))
    defer srv.Close()
    real.issuer, adv = srv.URL, srv.URL

    prov := &Provider{Issuer: srv.URL, ClientIDs: []string{"murmur-android",
        "murmur-ios"},
        Leeway: 60 * time.Second, httpc: srv.Client()}
    if err := prov.Discover(); err != nil {
        panic(err)
    }
    nonces := NewNonceStore()
    now := time.Now()
    // backend issues a nonce to the app before login (Listing 12.3)
    fresh := func() string {
        b := make([]byte, 16)
        rand.Read(b)
        n := b64(b)
        nonces.Put(n, now.Add(5*time.Minute))
        return n
    }
    claims := func(aud any, nonce string) map[string]any {
        return map[string]any{"iss": srv.URL, "sub": "248289761001", "aud": aud,
            "exp": now.Add(5 * time.Minute).Unix(),
            "iat": now.Unix(), "auth_time": now.Unix(), "nonce": nonce,
            "email": "alice@gmail.com", "email_verified": true}
    }
    try := func(label, tok string, o VerifyOpts) {
        c, err := prov.Verify(tok, nonces, o, now)
        if err != nil {
            fmt.Printf("  %-52s REJECT  %v\n", label, err)
        } else {
            fmt.Printf("  %-52s ACCEPT  sub=%s\n", label, c.Sub)
        }
    }

    fmt.Println("── ID token verification at Murmur's backend ──")
    n := fresh()
    good := real.sign("k1", claims("murmur-android", n), "ES256")
    try("valid token from the Murmur Android app", good,
        VerifyOpts{RawNonce: n})
    try("same token presented again (replay)", good, VerifyOpts{RawNonce: n})

    n = fresh()
    try("token issued to another app (aud=photo-app)", real.sign("k1",
        claims("photo-app", n), "ES256"), VerifyOpts{RawNonce: n})
    n = fresh()
    m := claims([]string{"murmur-android", "photo-app"}, n)
    m["azp"] = "photo-app"
    try("multi-aud token, azp=photo-app", real.sign("k1", m, "ES256"),
        VerifyOpts{RawNonce: n})
    n = fresh()
    try("nonce from a different login attempt", real.sign("k1",
        claims("murmur-android", "attacker-nonce"), "ES256"),
        VerifyOpts{RawNonce: n})
    n = fresh()
    m = claims("murmur-android", n)
    m["exp"] = now.Add(-10 * time.Minute).Unix()
    try("expired token", real.sign("k1", m, "ES256"), VerifyOpts{RawNonce: n})
    n = fresh()
    try(`alg "none"`, real.sign("k1", claims("murmur-android", n), "none"),
        VerifyOpts{RawNonce: n})

    evil := &idp{keys: map[string]*ecdsa.PrivateKey{"k1": newKey()}}
    n = fresh()
    try("forged: attacker key, real iss and kid", evil.sign("k1",
        claims("murmur-android", n), "ES256"), VerifyOpts{RawNonce: n})

    real.keys["k2"] = newKey() // IdP rotates signing keys
    prov.lastFetch = now.Add(-time.Minute)
    n = fresh()
    try("after IdP key rotation (new kid k2)", real.sign("k2",
        claims("murmur-android", n), "ES256"), VerifyOpts{RawNonce: n})

    fmt.Println(
        "── Step-up (§12.8): keys:write requires auth within 5 min and " +
        "acr=phr ──")
    n = fresh()
    m = claims("murmur-android", n)
    m["auth_time"] = now.Add(-2 * time.Hour).Unix()
    try("auth_time 2 h ago (SSO session reused)", real.sign("k1", m, "ES256"),
        VerifyOpts{RawNonce: n, MaxAuthAge: 5 * time.Minute})
    n = fresh()
    m = claims("murmur-android", n)
    m["acr"] = "phr"
    m["amr"] = []string{"hwk", "user"}
    try("fresh passkey login, acr=phr", real.sign("k1", m, "ES256"),
        VerifyOpts{RawNonce: n, MaxAuthAge: 5 * time.Minute, RequireAcr: "phr"})

    fmt.Println("── Discovery pinning ──")
    adv = "https://evil.example"
    p2 := &Provider{Issuer: srv.URL, ClientIDs: prov.ClientIDs,
        httpc: srv.Client()}
    fmt.Printf("  %-52s %v\n", "discovery doc claims a different issuer",
        p2.Discover())

    fmt.Println("── Account linking (Fig 12.3) ──")
    victim := &IDClaims{Iss: "https://accounts.google.com", Sub: "g-111",
        Email: "alice@gmail.com", EmailVerified: json.RawMessage("true")}
    // Naive: merge any login into the account with the same email.
    naive := map[string]string{}
    // Mallory pre-registers with Alice's email, unverified
    naive["alice@gmail.com"] = "acct-mallory"
    fmt.Printf(
        "  naive email merge: Alice's Google login lands in    %s  ← " +
        "pre-account takeover\n", naive[victim.Email])

    acc := NewAccounts()
    // same attack against the safe logic
    mal := acc.CreatePasswordAccount("alice@gmail.com", false)
    a, how, err := acc.SignIn(victim, nil, now)
    fmt.Printf(
        "  safe: Mallory's unverified pre-account %s; Alice → %s (%s) err=%v\n",
        mal.ID, a.ID, how, err)

    sneaky := &IDClaims{Iss: "https://idp.sketchy.example", Sub: "s-9",
        Email: "alice@gmail.com", EmailVerified: json.RawMessage("false")}
    _, _, err = acc.SignIn(sneaky, nil, now)
    fmt.Printf("  safe: other IdP, email_verified=false, same email   → %v\n",
        err)
    corp := &IDClaims{Iss: "https://login.corp.example", Sub: "c-42",
        Email: "alice@gmail.com", EmailVerified: json.RawMessage(`"true"`)}
    _, _, err = acc.SignIn(corp, &Session{AccountID: a.ID,
        AuthTime: now.Add(-2 * time.Minute)}, now)
    fmt.Printf("  safe: non-authoritative IdP says gmail.com verified → %v\n",
        err)

    // Bob verified his email via a link
    bob := acc.CreatePasswordAccount("bob@gmail.com", true)
    bobG := &IDClaims{Iss: "https://accounts.google.com", Sub: "g-222",
        Email: "bob@gmail.com", EmailVerified: json.RawMessage("true")}
    _, _, err = acc.SignIn(bobG, nil, now)
    fmt.Printf("  safe: Bob's Google login, no session on %s     → %v\n",
        bob.ID, err)
    b, how, err := acc.SignIn(bobG, &Session{AccountID: bob.ID,
        AuthTime: now.Add(-2 * time.Minute)}, now)
    fmt.Printf(
        "  safe: Bob's Google login + Bob signed in 2 min ago  → %s (%s) " +
        "err=%v\n", b.ID, how, err)
}
