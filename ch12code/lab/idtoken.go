// idtoken.go
// Listing 12.1 — Go: backend verification of an ID token sent by the Murmur app.
// Discovery-driven (issuer pinned in config, JWKS URL taken from discovery), ES256/RS256
// allowlist bound to key type, iss, aud allowlist, azp, exp/iat, single-use nonce, auth_time.
// Standard library only so every check is visible; use a maintained OIDC library in production.
package main

import (
       "crypto"
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rsa"
       "crypto/sha256"
       "encoding/base64"
       "encoding/hex"
       "encoding/json"
       "errors"
       "fmt"
       "math/big"
       "net/http"
       "strings"
       "sync"
       "time"
)

type Provider struct {
       Issuer      string   // configured, exact: "https://accounts.google.com", "https://appleid.apple.com"
       ClientIDs   []string // ONLY our apps' client IDs (Android, iOS / bundle ID)
       HashedNonce bool     // Sign in with Apple pattern: IdP sees SHA-256(nonce), backend holds raw nonce
       Leeway      time.Duration

       httpc     *http.Client
       mu        sync.Mutex
       jwksURL   string
       keys      map[string]crypto.PublicKey
       lastFetch time.Time
}

type IDClaims struct {
       Iss           string          `json:"iss"`
       Sub           string          `json:"sub"`
       Aud           json.RawMessage `json:"aud"`
       Azp           string          `json:"azp"`
       Exp           int64           `json:"exp"`
       Iat           int64           `json:"iat"`
       AuthTime      int64           `json:"auth_time"`
       Nonce         string          `json:"nonce"`
       Acr           string          `json:"acr"`
       Amr           []string        `json:"amr"`
       Email         string          `json:"email"`
       EmailVerified json.RawMessage `json:"email_verified"` // Apple has sent "true" as a string
}

func (c *IDClaims) Verified() bool {
       v := strings.Trim(string(c.EmailVerified), `"`)
       return v == "true"
}

// Discover reads /.well-known/openid-configuration and REQUIRES that its "issuer" equals the
// configured issuer (OIDC Discovery §4.3). The JWKS URL comes from here, never from a token.
func (p *Provider) Discover() error {
       if p.httpc == nil {
              p.httpc = &http.Client{Timeout: 5 * time.Second}
       }
       resp, err := p.httpc.Get(strings.TrimSuffix(p.Issuer, "/") + "/.well-known/openid-configuration")
       if err != nil {
              return err
       }
       defer resp.Body.Close()
       var md struct {
              Issuer  string `json:"issuer"`
              JWKSURI string `json:"jwks_uri"`
       }
       if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
              return err
       }
       if md.Issuer != p.Issuer {
              return fmt.Errorf("discovery issuer %q != configured %q", md.Issuer, p.Issuer)
       }
       if !strings.HasPrefix(md.JWKSURI, "https://") {
              return errors.New("jwks_uri must be https")
       }
       p.jwksURL = md.JWKSURI
       return p.fetchKeys()
}

func (p *Provider) fetchKeys() error {
       resp, err := p.httpc.Get(p.jwksURL)
       if err != nil {
              return err
       }
       defer resp.Body.Close()
       var set struct {
              Keys []struct{ Kty, Kid, Use, Crv, X, Y, N, E string } `json:"keys"`
       }
       if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
              return err
       }
       keys := map[string]crypto.PublicKey{}
       for _, k := range set.Keys {
              if k.Use != "" && k.Use != "sig" {
                     continue
              }
              switch {
              case k.Kty == "EC" && k.Crv == "P-256":
                     x, y := b64int(k.X), b64int(k.Y)
                     if x != nil && y != nil && elliptic.P256().IsOnCurve(x, y) {
                            keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
                     }
              case k.Kty == "RSA":
                     n, e := b64int(k.N), b64int(k.E)
                     if n != nil && e != nil && n.BitLen() >= 2048 {
                            keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
                     }
              }
       }
       p.keys, p.lastFetch = keys, time.Now()
       return nil
}

// key returns the key for kid; an unknown kid triggers one rate-limited refetch (key rotation).
func (p *Provider) key(kid string) (crypto.PublicKey, error) {
       p.mu.Lock()
       defer p.mu.Unlock()
       if k, ok := p.keys[kid]; ok {
              return k, nil
       }
       if time.Since(p.lastFetch) >= 30*time.Second || p.lastFetch.IsZero() {
              if err := p.fetchKeys(); err != nil {
                     return nil, err
              }
              if k, ok := p.keys[kid]; ok {
                     return k, nil
              }
       }
       return nil, fmt.Errorf("unknown kid %q", kid)
}

func b64int(s string) *big.Int {
       b, err := base64.RawURLEncoding.DecodeString(s)
       if err != nil || len(b) == 0 {
              return nil
       }
       return new(big.Int).SetBytes(b)
}

// NonceStore issues single-use, short-lived nonces bound to a pre-login session.
type NonceStore struct {
       mu sync.Mutex
       m  map[string]time.Time
}

func NewNonceStore() *NonceStore { return &NonceStore{m: map[string]time.Time{}} }
func (s *NonceStore) Put(n string, exp time.Time) {
       s.mu.Lock()
       s.m[n] = exp
       s.mu.Unlock()
}

// Take consumes the nonce: a second presentation of the same ID token fails.
func (s *NonceStore) Take(n string, now time.Time) bool {
       s.mu.Lock()
       defer s.mu.Unlock()
       exp, ok := s.m[n]
       delete(s.m, n)
       return ok && now.Before(exp)
}

type VerifyOpts struct {
       RawNonce   string        // the nonce the backend issued to this app session
       MaxAuthAge time.Duration // >0: require auth_time within this window (step-up, §12.8)
       RequireAcr string        // non-empty: require this acr value
}

func (p *Provider) Verify(tok string, nonces *NonceStore, o VerifyOpts, now time.Time) (*IDClaims, error) {
       parts := strings.Split(tok, ".")
       if len(parts) != 3 {
              return nil, errors.New("malformed")
       }
       hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
       cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
       sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
       if err1 != nil || err2 != nil || err3 != nil {
              return nil, errors.New("bad encoding")
       }
       var hdr struct{ Alg, Kid string }
       if json.Unmarshal(hb, &hdr) != nil {
              return nil, errors.New("bad header")
       }
       // 1. Signature: key chosen by kid from the issuer's JWKS; alg must match the key type.
       key, err := p.key(hdr.Kid)
       if err != nil {
              return nil, err
       }
       digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
       switch k := key.(type) {
       case *ecdsa.PublicKey:
              if hdr.Alg != "ES256" || len(sig) != 64 ||
                     !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
                     return nil, errors.New("bad signature")
              }
       case *rsa.PublicKey:
              if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
                     return nil, errors.New("bad signature")
              }
       default: // never fall through to "valid" for a key type we don't handle
              return nil, errors.New("unsupported key type")
       }
       var c IDClaims
       if json.Unmarshal(cb, &c) != nil {
              return nil, errors.New("bad claims")
       }
       // 2. Issuer: exact match with the configured issuer.
       if c.Iss != p.Issuer {
              return nil, fmt.Errorf("wrong iss %q", c.Iss)
       }
       // 3. Audience: must contain one of OUR client IDs; every listed aud must be trusted.
       auds := audList(c.Aud)
       ours := ""
       for _, a := range auds {
              if contains(p.ClientIDs, a) {
                     ours = a
              } else if len(auds) > 1 {
                     return nil, fmt.Errorf("untrusted additional audience %q", a)
              }
       }
       if ours == "" {
              return nil, fmt.Errorf("aud %v is not a Murmur client", auds)
       }
       // 4. azp: with several audiences, the authorized party must be one of our clients.
       if (len(auds) > 1 || c.Azp != "") && !contains(p.ClientIDs, c.Azp) {
              return nil, fmt.Errorf("azp %q is not a Murmur client", c.Azp)
       }
       // 5. Time: exp in the future, iat not in the future and not ancient.
       lw := int64(p.Leeway.Seconds())
       t := now.Unix()
       if t > c.Exp+lw {
              return nil, errors.New("expired")
       }
       if c.Iat > t+lw || c.Iat < t-3600 {
              return nil, errors.New("iat out of range")
       }
       // 6. Nonce: matches the nonce we issued to this session, and is consumed (single use).
       want := o.RawNonce
       if p.HashedNonce {
              h := sha256.Sum256([]byte(o.RawNonce))
              want = hex.EncodeToString(h[:])
       }
       if o.RawNonce == "" || c.Nonce != want || !nonces.Take(o.RawNonce, now) {
              return nil, errors.New("nonce missing, mismatched or already used")
       }
       // 7. Assurance (step-up): fresh enough authentication, required acr.
       if o.MaxAuthAge > 0 && (c.AuthTime == 0 || t-c.AuthTime > int64(o.MaxAuthAge.Seconds())+lw) {
              return nil, errors.New("authentication too old (auth_time)")
       }
       if o.RequireAcr != "" && c.Acr != o.RequireAcr {
              return nil, fmt.Errorf("acr %q, need %q", c.Acr, o.RequireAcr)
       }
       return &c, nil
}

func audList(raw json.RawMessage) []string {
       var one string
       if json.Unmarshal(raw, &one) == nil {
              return []string{one}
       }
       var many []string
       json.Unmarshal(raw, &many)
       return many
}

func contains(xs []string, s string) bool {
       for _, x := range xs {
              if x == s {
                     return true
              }
       }
       return false
}
