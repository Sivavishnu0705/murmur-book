// dpop.go
// Listing 13.3 — Go: DPoP verification middleware (RFC 9449) for murmur-api.
// Checks: typ, alg (ES256 only), embedded public JWK (no private members), signature, htm, htu,
// iat window, jti replay cache, server nonce, ath, and cnf.jkt match with the access token.
// Standard library only so every check is visible.
package main

import (
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/sha256"
       "encoding/base64"
       "encoding/json"
       "errors"
       "fmt"
       "math/big"
       "net/http"
       "net/url"
       "strings"
       "sync"
       "time"
)

var b64 = base64.RawURLEncoding

type JWK struct {
       Kty string `json:"kty"`
       Crv string `json:"crv"`
       X   string `json:"x"`
       Y   string `json:"y"`
       D   string `json:"d,omitempty"` // must be absent
}

// Thumbprint is the RFC 7638 JWK thumbprint: SHA-256 over the required members, in
// lexicographic order, with no whitespace. For EC keys: crv, kty, x, y.
func (k JWK) Thumbprint() string {
       canon := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, k.Crv, k.Kty, k.X, k.Y)
       h := sha256.Sum256([]byte(canon))
       return b64.EncodeToString(h[:])
}

func (k JWK) Public() (*ecdsa.PublicKey, error) {
       if k.Kty != "EC" || k.Crv != "P-256" || k.D != "" {
              return nil, errors.New("jwk must be a public EC P-256 key")
       }
       xb, err1 := b64.DecodeString(k.X)
       yb, err2 := b64.DecodeString(k.Y)
       if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
              return nil, errors.New("bad jwk coordinates")
       }
       x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
       if !elliptic.P256().IsOnCurve(x, y) { // invalid-curve check (Ch 2)
              return nil, errors.New("point not on curve")
       }
       return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// ReplayCache remembers jti values for the acceptance window. In production: a shared store
// (e.g. Redis SET NX with TTL) across all murmur-api instances, keyed per jkt.
type ReplayCache struct {
       mu   sync.Mutex
       seen map[string]time.Time
}

func NewReplayCache() *ReplayCache { return &ReplayCache{seen: map[string]time.Time{}} }

func (c *ReplayCache) FirstUse(key string, until time.Time, now time.Time) bool {
       c.mu.Lock()
       defer c.mu.Unlock()
       for k, exp := range c.seen { // simple sweep; fine for a demo
              if now.After(exp) {
                     delete(c.seen, k)
              }
       }
       if _, dup := c.seen[key]; dup {
              return false
       }
       c.seen[key] = until
       return true
}

// Nonces: server-issued, short-lived values that make pre-computed proofs useless.
type Nonces struct {
       mu      sync.Mutex
       current string
       prev    string
}

func (n *Nonces) Rotate() {
       b := make([]byte, 16)
       rand.Read(b)
       n.mu.Lock()
       n.prev, n.current = n.current, b64.EncodeToString(b)
       n.mu.Unlock()
}
func (n *Nonces) Current() string { n.mu.Lock(); defer n.mu.Unlock(); return n.current }
func (n *Nonces) Valid(v string) bool {
       n.mu.Lock()
       defer n.mu.Unlock()
       return v != "" && (v == n.current || v == n.prev) // accept the previous one across a rotation
}

type Verifier struct {
       Window       time.Duration // accepted |now - iat|, e.g. 60 s
       Replay       *ReplayCache
       Nonces       *Nonces // nil: server nonces not required
       PublicOrigin string  // e.g. "https://api.murmur.example": the URL the CLIENT used, not the
       // internal one behind the CDN/load balancer
}

type ProofError struct{ Code, Msg string }

func (e *ProofError) Error() string { return e.Code + ": " + e.Msg }

// CanonicalHTU: scheme and host lower-cased, the scheme's default port dropped (443 for https,
// 80 for http; others such as :8443 kept), no query or fragment.
func CanonicalHTU(raw string) (string, error) {
       u, err := url.Parse(raw)
       if err != nil || u.Scheme == "" || u.Host == "" {
              return "", errors.New("bad htu")
       }
       scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
       if (scheme == "https" && u.Port() == "443") || (scheme == "http" && u.Port() == "80") {
              host = strings.TrimSuffix(host, ":"+u.Port()) // keeps IPv6 brackets intact
       }
       return scheme + "://" + host + u.EscapedPath(), nil
}

// Verify checks one DPoP proof. accessToken is "" at the token endpoint (no ath there).
// Returns the proof key's thumbprint, which the caller compares with cnf.jkt.
func (v *Verifier) Verify(proof, method, path, accessToken string, now time.Time) (string, error) {
       bad := func(f string, a ...any) (string, error) {
              return "", &ProofError{"invalid_dpop_proof", fmt.Sprintf(f, a...)}
       }
       parts := strings.Split(proof, ".")
       if len(parts) != 3 {
              return bad("malformed")
       }
       hb, e1 := b64.DecodeString(parts[0])
       cb, e2 := b64.DecodeString(parts[1])
       sig, e3 := b64.DecodeString(parts[2])
       if e1 != nil || e2 != nil || e3 != nil {
              return bad("bad encoding")
       }
       var hdr struct {
              Typ string `json:"typ"`
              Alg string `json:"alg"`
              JWK JWK    `json:"jwk"`
       }
       if json.Unmarshal(hb, &hdr) != nil {
              return bad("bad header")
       }
       if hdr.Typ != "dpop+jwt" {
              return bad("typ %q", hdr.Typ)
       }
       if hdr.Alg != "ES256" { // allowlist; "none" and MACs are impossible here
              return bad("alg %q", hdr.Alg)
       }
       pub, err := hdr.JWK.Public()
       if err != nil {
              return bad("%v", err)
       }
       d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
       if len(sig) != 64 || !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
              return bad("signature") // JWS ES256 is raw r‖s, not DER (Listings 13.1/13.2)
       }
       var c struct {
              Jti   string `json:"jti"`
              Htm   string `json:"htm"`
              Htu   string `json:"htu"`
              Iat   int64  `json:"iat"`
              Ath   string `json:"ath"`
              Nonce string `json:"nonce"`
       }
       if json.Unmarshal(cb, &c) != nil {
              return bad("bad claims")
       }
       if c.Htm != method {
              return bad("htm %q, request is %s", c.Htm, method)
       }
       want, _ := CanonicalHTU(v.PublicOrigin + path)
       got, err := CanonicalHTU(c.Htu)
       if err != nil || got != want {
              return bad("htu %q, request is %s", c.Htu, want)
       }
       skew := now.Sub(time.Unix(c.Iat, 0))
       if skew > v.Window || skew < -v.Window {
              return bad("iat outside ±%v (skew %v)", v.Window, skew.Round(time.Second))
       }
       if v.Nonces != nil && !v.Nonces.Valid(c.Nonce) {
              return "", &ProofError{"use_dpop_nonce", "fresh server nonce required"}
       }
       if accessToken != "" {
              h := sha256.Sum256([]byte(accessToken))
              if c.Ath != b64.EncodeToString(h[:]) {
                     return bad("ath does not match the presented access token")
              }
       }
       jkt := hdr.JWK.Thumbprint()
       if len(c.Jti) < 16 || !v.Replay.FirstUse(jkt+"|"+c.Jti, now.Add(2*v.Window), now) {
              return bad("jti missing or replayed")
       }
       return jkt, nil
}

// ---- resource-server middleware ----

type AccessToken struct {
       Sub   string
       Jkt   string // cnf.jkt; "" = plain bearer token
       Exp   time.Time
       Scope string
}

// TokenLookup stands in for Listing 10.2's JWT validation (which now also reads cnf.jkt).
type TokenLookup func(string) (*AccessToken, bool)

func (v *Verifier) Middleware(lookup TokenLookup, clock func() time.Time, next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
              now := clock()
              fail := func(scheme, code, msg string) {
                     if v.Nonces != nil {
                            w.Header().Set("DPoP-Nonce", v.Nonces.Current())
                     }
                     w.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s error="%s", error_description="%s", algs="ES256"`, scheme, code, msg))
                     http.Error(w, code+": "+msg, http.StatusUnauthorized)
              }
              scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
              at, ok := lookup(tok)
              if !ok || now.After(at.Exp) {
                     fail("DPoP", "invalid_token", "unknown or expired token")
                     return
              }
              if at.Jkt == "" { // legacy bearer token (the lab's "before" state)
                     if scheme != "Bearer" {
                            fail("Bearer", "invalid_token", "bearer token")
                            return
                     }
                     next.ServeHTTP(w, r)
                     return
              }
              // A DPoP-bound token MUST arrive with scheme DPoP and exactly one proof — downgrading to
              // "Bearer" must not skip the proof.
              proofs := r.Header.Values("DPoP")
              if !strings.EqualFold(scheme, "DPoP") || len(proofs) != 1 {
                     fail("DPoP", "invalid_token", "DPoP-bound token requires DPoP scheme and one proof")
                     return
              }
              jkt, err := v.Verify(proofs[0], r.Method, r.URL.EscapedPath(), tok, now)
              if err != nil {
                     pe := err.(*ProofError)
                     fail("DPoP", pe.Code, pe.Msg)
                     return
              }
              if jkt != at.Jkt {
                     fail("DPoP", "invalid_token", "proof key does not match cnf.jkt")
                     return
              }
              next.ServeHTTP(w, r)
       })
}
