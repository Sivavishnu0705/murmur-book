// Listing 10.2 — Go: resource-server JWT access-token validation (RFC 9068
// profile): alg allowlist bound to key type, issuer, audience, expiry, typ,
// scope, and a JWKS cache. Standard library only, so every check is visible. In
// production, use a maintained JOSE library, configured with the same rules.
package main

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "math/big"
    "net/http"
    "strings"
    "sync"
    "time"
)

type Policy struct {
    Issuer   string        // exact match, e.g. https://auth.murmur.example
    // this resource server, e.g. https://api.murmur.example
    Audience string
    // from the AS metadata (RFC 8414), never from the token
    JWKSURL  string
    Leeway   time.Duration // clock skew tolerance (mobile clocks, Ch 1)
    // Accepted JWT "typ" header values. Default (nil): RFC 9068's "at+jwt"
    // only. Some authorization servers still emit "JWT"; accepting it shifts
    // the burden of telling access tokens from ID tokens entirely onto the aud
    // check below.
    AllowedTyp []string
}

type Claims struct {
    Iss      string          `json:"iss"`
    Sub      string          `json:"sub"`
    Aud      json.RawMessage `json:"aud"` // string or array
    Exp      int64           `json:"exp"`
    Nbf      int64           `json:"nbf"`
    Iat      int64           `json:"iat"`
    Jti      string          `json:"jti"`
    ClientID string          `json:"client_id"`
    Scope    string          `json:"scope"`
}

// ---------- JWKS cache: keys by kid, refreshed on unknown kid (rate-limited)
// ----------
type JWKS struct {
    url       string
    mu        sync.Mutex
    keys      map[string]crypto.PublicKey
    lastFetch time.Time
    client    *http.Client
}

func NewJWKS(url string) *JWKS {
    return &JWKS{url: url, keys: map[string]crypto.PublicKey{},
        client: &http.Client{Timeout: 5 * time.Second}}
}

func (j *JWKS) key(kid string) (crypto.PublicKey, error) {
    j.mu.Lock()
    defer j.mu.Unlock()
    if k, ok := j.keys[kid]; ok {
        return k, nil
    }
    // Unknown kid: the AS may have rotated keys. Refetch, but at most once per
    // 30 s, so a flood of tokens with random kids can't turn the RS into a
    // JWKS-fetching amplifier.
    if time.Since(j.lastFetch) < 30*time.Second {
        return nil, fmt.Errorf("unknown kid %q", kid)
    }
    j.lastFetch = time.Now()
    if err := j.fetch(); err != nil {
        return nil, err
    }
    if k, ok := j.keys[kid]; ok {
        return k, nil
    }
    return nil, fmt.Errorf("unknown kid %q", kid)
}

func (j *JWKS) fetch() error {
    resp, err := j.client.Get(j.url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    var set struct {
        Keys []struct{ Kty, Kid, Use, Alg, Crv, X, Y, N,
            E string } `json:"keys"`
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
            // invalid-curve check (Ch 2)
            if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
                continue
            }
            keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
        case k.Kty == "RSA":
            n, e := b64int(k.N), b64int(k.E)
            if n == nil || e == nil || n.BitLen() < 2048 {
                continue
            }
            keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
        }
    }
    j.keys = keys // replaces the set: keys removed by the AS stop working
    return nil
}

func b64int(s string) *big.Int {
    b, err := base64.RawURLEncoding.DecodeString(s)
    if err != nil || len(b) == 0 {
        return nil
    }
    return new(big.Int).SetBytes(b)
}

// ---------- validation ----------
func Validate(token string, p Policy, jwks *JWKS, now time.Time) (*Claims,
    error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return nil, errors.New("malformed JWT")
    }
    hb, err := base64.RawURLEncoding.DecodeString(parts[0])
    if err != nil {
        return nil, errors.New("bad header encoding")
    }
    var hdr struct{ Alg, Kid, Typ string }
    if err := json.Unmarshal(hb, &hdr); err != nil {
        return nil, errors.New("bad header")
    }
    // RFC 9068: access tokens are typed "at+jwt", so an ID token (or any other
    // JWT signed by the same AS) can't be replayed as an access token.
    allowed := p.AllowedTyp
    if allowed == nil {
        allowed = []string{"at+jwt", "application/at+jwt"}
    }
    typOK := false
    for _, t := range allowed {
        typOK = typOK || strings.EqualFold(hdr.Typ, t)
    }
    if !typOK {
        return nil, fmt.Errorf("wrong typ %q", hdr.Typ)
    }
    key, err := jwks.key(hdr.Kid)
    if err != nil {
        return nil, err
    }
    sig, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil {
        return nil, errors.New("bad signature encoding")
    }
    digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
    // alg allowlist, and the alg MUST match the key's type. The token never
    // chooses the algorithm for a key: that's how "alg: none" and
    // HS256-with-a-public-key attacks work.
    switch k := key.(type) {
    case *ecdsa.PublicKey:
        if hdr.Alg != "ES256" || len(sig) != 64 {
            return nil, fmt.Errorf("alg %q not allowed for EC key", hdr.Alg)
        }
        // JWS: raw r‖s (Ch 2)
        r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
        if !ecdsa.Verify(k, digest[:], r, s) {
            return nil, errors.New("bad signature")
        }
    case *rsa.PublicKey:
        if hdr.Alg != "RS256" {
            return nil, fmt.Errorf("alg %q not allowed for RSA key", hdr.Alg)
        }
        if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:],
            sig); err != nil {
            return nil, errors.New("bad signature")
        }
    default:
        return nil, errors.New("unsupported key")
    }
    cb, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, errors.New("bad claims encoding")
    }
    var c Claims
    if err := json.Unmarshal(cb, &c); err != nil {
        return nil, errors.New("bad claims")
    }
    if c.Iss != p.Issuer {
        return nil, fmt.Errorf("wrong issuer %q", c.Iss)
    }
    if !hasAudience(c.Aud, p.Audience) {
        return nil,
            errors.New("token not issued for this resource server (aud)")
    }
    t := now.Unix()
    if c.Exp == 0 || t > c.Exp+int64(p.Leeway.Seconds()) {
        return nil, errors.New("token expired")
    }
    if c.Nbf != 0 && t+int64(p.Leeway.Seconds()) < c.Nbf {
        return nil, errors.New("token not yet valid")
    }
    if c.Sub == "" || c.ClientID == "" {
        return nil, errors.New("missing sub or client_id")
    }
    return &c, nil
}

func hasAudience(raw json.RawMessage, want string) bool {
    var one string
    if json.Unmarshal(raw, &one) == nil {
        return one == want
    }
    var many []string
    if json.Unmarshal(raw, &many) == nil {
        for _, a := range many {
            if a == want {
                return true
            }
        }
    }
    return false
}

func (c *Claims) HasScope(s string) bool {
    for _, x := range strings.Fields(c.Scope) {
        if x == s {
            return true
        }
    }
    return false
}

type claimsKey struct{}

// RequireToken validates the bearer token and the required scope, then calls
// next.
func RequireToken(p Policy, jwks *JWKS, scope string,
    next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        // DPoP-bound tokens use "DPoP " (Ch 13)
        if !strings.HasPrefix(auth, "Bearer ") {
            w.Header().Set("WWW-Authenticate", `Bearer`)
            http.Error(w, "missing token", http.StatusUnauthorized)
            return
        }
        c, err := Validate(strings.TrimPrefix(auth, "Bearer "), p, jwks,
            time.Now())
        if err != nil {
            w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
            // log details; return less in prod
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        if !c.HasScope(scope) {
            w.Header().Set("WWW-Authenticate",
                fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`,
                scope))
            http.Error(w, "insufficient scope", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(),
            claimsKey{}, c)))
    })
}
