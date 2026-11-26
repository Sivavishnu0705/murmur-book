//go:build !serve

// Listing 10.4 — Go: test driver. A mock authorization server mints ES256 access tokens and
// serves a JWKS; the resource server (Listing 10.2) validates each scenario.
package main

import (
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/hmac"
       "crypto/rand"
       "crypto/sha256"
       "encoding/base64"
       "encoding/json"
       "fmt"
       "io"
       "net/http"
       "net/http/httptest"
       "strings"
       "sync/atomic"
       "time"
)

var b64 = base64.RawURLEncoding

type signingKey struct {
       kid string
       key *ecdsa.PrivateKey
}

func newSigningKey(kid string) signingKey {
       k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       return signingKey{kid, k}
}

func jwk(s signingKey) map[string]string {
       return map[string]string{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
              "x": b64.EncodeToString(s.key.X.FillBytes(make([]byte, 32))),
              "y": b64.EncodeToString(s.key.Y.FillBytes(make([]byte, 32)))}
}

func mint(s signingKey, hdr, claims map[string]any) string {
       h, _ := json.Marshal(hdr)
       c, _ := json.Marshal(claims)
       in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
       d := sha256.Sum256([]byte(in))
       r, ss, _ := ecdsa.Sign(rand.Reader, s.key, d[:])
       sig := append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
       return in + "." + b64.EncodeToString(sig)
}

func main() {
       const iss, aud = "https://auth.murmur.example", "https://api.murmur.example"
       k1 := newSigningKey("2026-11-a")
       current := []signingKey{k1}
       var fetches atomic.Int32
       as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
              fetches.Add(1)
              var keys []map[string]string
              for _, k := range current {
                     keys = append(keys, jwk(k))
              }
              json.NewEncoder(w).Encode(map[string]any{"keys": keys})
       }))
       defer as.Close()

       p := Policy{Issuer: iss, Audience: aud, JWKSURL: as.URL, Leeway: 60 * time.Second}
       jwks := NewJWKS(p.JWKSURL)
       api := httptest.NewServer(RequireToken(p, jwks, "messages:send",
              http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                     c := r.Context().Value(claimsKey{}).(*Claims)
                     fmt.Fprintf(w, "message accepted from %s via %s", c.Sub, c.ClientID)
              })))
       defer api.Close()

       now := time.Now().Unix()
       claims := func(mod func(map[string]any)) map[string]any {
              c := map[string]any{"iss": iss, "sub": "alice", "aud": aud, "client_id": "murmur-ios",
                     "scope": "messages:send contacts:read", "iat": now, "exp": now + 300, "jti": "j1"}
              if mod != nil {
                     mod(c)
              }
              return c
       }
       at := map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "2026-11-a"}
       call := func(desc, tok string) {
              req, _ := http.NewRequest("POST", api.URL+"/v1/messages", nil)
              req.Header.Set("Authorization", "Bearer "+tok)
              resp, err := http.DefaultClient.Do(req)
              if err != nil {
                     panic(err)
              }
              b, _ := io.ReadAll(resp.Body)
              resp.Body.Close()
              fmt.Printf("%-3s %-44s → %d %s\n", strings.SplitN(desc, " ", 2)[0], strings.SplitN(desc, " ", 2)[1],
                     resp.StatusCode, strings.TrimSpace(string(b)))
       }

       call("1 valid access token", mint(k1, at, claims(nil)))
       call("2 expired token", mint(k1, at, claims(func(c map[string]any) { c["exp"] = now - 3600 })))
       call("3 token for another resource server (aud)", mint(k1, at, claims(func(c map[string]any) { c["aud"] = "https://admin.murmur.example" })))
       call("4 token from another issuer", mint(k1, at, claims(func(c map[string]any) { c["iss"] = "https://evil.example" })))
       call("5 ID token replayed as access token", mint(k1, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "2026-11-a"}, claims(nil)))
       call("6 missing required scope", mint(k1, at, claims(func(c map[string]any) { c["scope"] = "contacts:read" })))

       // 7. Scope escalation by editing the payload: signature no longer matches.
       good := strings.Split(mint(k1, at, claims(nil)), ".")
       evil, _ := json.Marshal(claims(func(c map[string]any) { c["scope"] = "messages:send admin:all" }))
       call("7 payload edited (scope escalation)", good[0]+"."+b64.EncodeToString(evil)+"."+good[2])

       // 8. alg:none — no signature at all.
       nh, _ := json.Marshal(map[string]any{"alg": "none", "typ": "at+jwt", "kid": "2026-11-a"})
       nc, _ := json.Marshal(claims(nil))
       call("8 alg: none", b64.EncodeToString(nh)+"."+b64.EncodeToString(nc)+".")

       // 9. Algorithm confusion: HS256 "signed" with the PUBLIC key as the HMAC secret.
       hh, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": "2026-11-a"})
       in := b64.EncodeToString(hh) + "." + b64.EncodeToString(nc)
       pub, _ := json.Marshal(jwk(k1))
       m := hmac.New(sha256.New, pub)
       m.Write([]byte(in))
       call("9 HS256 with the public key as secret", in+"."+b64.EncodeToString(m.Sum(nil)))

       // 10. Key rotation: the AS publishes a new key and signs with it.
       k2 := newSigningKey("2026-12-b")
       current = []signingKey{k1, k2}
       time.Sleep(10 * time.Millisecond)
       jwks.mu.Lock()
       jwks.lastFetch = time.Time{} // simulate: the last fetch was long ago
       jwks.mu.Unlock()
       before := fetches.Load()
       call("10 after AS key rotation (new kid)", mint(k2, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "2026-12-b"}, claims(nil)))
       fmt.Printf("    JWKS fetches for the new kid: %d\n", fetches.Load()-before)

       // 11. Flood of random kids: at most one refetch per 30 s.
       before = fetches.Load()
       for i := 0; i < 50; i++ {
              tok := mint(k1, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": fmt.Sprintf("bogus-%d", i)}, claims(nil))
              req, _ := http.NewRequest("POST", api.URL+"/v1/messages", nil)
              req.Header.Set("Authorization", "Bearer "+tok)
              resp, _ := http.DefaultClient.Do(req)
              resp.Body.Close()
       }
       fmt.Printf("%-3s %-44s → JWKS fetches: %d (rate-limited)\n", "11", "50 tokens with random kids", fetches.Load()-before)
}
