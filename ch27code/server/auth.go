// auth.go
// Listing 27.2 — Go: auth integration for murmur-api. Every request passes four checks before a
// handler runs: (1) the access token is a valid ES256 JWT from murmur-auth for this audience;
// (2) the DPoP proof is valid and its key matches cnf.jkt (Listing 13.3's Verifier); (3) the
// token's device is enrolled and not revoked; (4) the scope, and for sensitive scopes a recent
// phishing-resistant authentication (RFC 9470 step-up), are present.
package main

import (
       "context"
       "crypto/ecdsa"
       "crypto/sha256"
       "encoding/json"
       "errors"
       "fmt"
       "math/big"
       "net/http"
       "slices"
       "strings"
       "time"
)

// IssuerConfig is what murmur-api trusts. murmur-auth is the only issuer: upstream OIDC
// providers (Ch 12) authenticate users TO murmur-auth; their ID tokens never reach the API.
type IssuerConfig struct {
       Issuer   string                      // "https://auth.murmur.example"
       Audience string                      // "https://api.murmur.example"
       Keys     map[string]*ecdsa.PublicKey // kid → key, refreshed from the issuer's JWKS
       Leeway   time.Duration               // clock skew tolerated on exp/iat (≤ 30 s)
}

type Claims struct {
       Iss      string `json:"iss"`
       Sub      string `json:"sub"` // Murmur account ID (internal; the (iss,sub) of the IdP maps to it, Ch 12)
       Aud      string `json:"aud"`
       Exp      int64  `json:"exp"`
       Iat      int64  `json:"iat"`
       Jti      string `json:"jti"`
       DeviceID string `json:"device_id"`
       Scope    string `json:"scope"`
       Acr      string `json:"acr"`
       AuthTime int64  `json:"auth_time"`
       Cnf      struct {
              Jkt string `json:"jkt"`
       } `json:"cnf"`
       scopes []string
}

type Caller struct {
       Account, Device string
       Claims          *Claims
}

type ctxKey struct{}
type slotKey struct{}

func CallerFrom(r *http.Request) *Caller { c, _ := r.Context().Value(ctxKey{}).(*Caller); return c }

var errToken = errors.New("invalid_token")

// VerifyAccessToken: a JWT with typ "at+jwt" (RFC 9068), alg ES256 only, known kid, correct
// iss and aud, unexpired, with a device_id and a cnf.jkt. Anything missing is a rejection.
func (c *IssuerConfig) VerifyAccessToken(tok string, now time.Time) (*Claims, error) {
       parts := strings.Split(tok, ".")
       if len(parts) != 3 {
              return nil, errToken
       }
       hb, e1 := b64.DecodeString(parts[0])
       cb, e2 := b64.DecodeString(parts[1])
       sig, e3 := b64.DecodeString(parts[2])
       if e1 != nil || e2 != nil || e3 != nil || len(sig) != 64 {
              return nil, errToken
       }
       var h struct{ Typ, Alg, Kid string }
       if json.Unmarshal(hb, &h) != nil || h.Typ != "at+jwt" || h.Alg != "ES256" {
              return nil, errToken
       }
       key, ok := c.Keys[h.Kid]
       if !ok {
              return nil, errToken
       }
       d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
       if !ecdsa.Verify(key, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
              return nil, errToken
       }
       var cl Claims
       if json.Unmarshal(cb, &cl) != nil {
              return nil, errToken
       }
       switch {
       case cl.Iss != c.Issuer, cl.Aud != c.Audience:
              return nil, errToken
       case now.After(time.Unix(cl.Exp, 0).Add(c.Leeway)), time.Unix(cl.Iat, 0).After(now.Add(c.Leeway)):
              return nil, errToken
       case cl.Sub == "", cl.DeviceID == "", cl.Cnf.Jkt == "": // every Murmur token is device-bound
              return nil, errToken
       }
       cl.scopes = strings.Fields(cl.Scope)
       return &cl, nil
}

// Authenticator is the middleware. Devices is the registry (Listing 27.3); a revoked device's
// tokens die immediately, without waiting out their 5-minute lifetime.
type Authenticator struct {
       Issuer  *IssuerConfig
       DPoP    *Verifier
       Devices *Registry
       Clock   func() time.Time
}

func (a *Authenticator) fail(w http.ResponseWriter, status int, challenge string) {
       if a.DPoP.Nonces != nil {
              w.Header().Set("DPoP-Nonce", a.DPoP.Nonces.Current())
       }
       w.Header().Set("WWW-Authenticate", challenge)
       writeErr(w, status, "UNAUTHENTICATED", false)
}

func (a *Authenticator) Require(scope string, next http.HandlerFunc) http.HandlerFunc {
       return func(w http.ResponseWriter, r *http.Request) {
              now := a.Clock()
              scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
              proofs := r.Header.Values("DPoP")
              if !strings.EqualFold(scheme, "DPoP") || len(proofs) != 1 { // no Bearer fallback, ever
                     a.fail(w, 401, `DPoP error="invalid_token", algs="ES256"`)
                     return
              }
              cl, err := a.Issuer.VerifyAccessToken(tok, now)
              if err != nil {
                     a.fail(w, 401, `DPoP error="invalid_token", algs="ES256"`)
                     return
              }
              jkt, err := a.DPoP.Verify(proofs[0], r.Method, r.URL.EscapedPath(), tok, now)
              if err != nil {
                     code := "invalid_dpop_proof"
                     var pe *ProofError
                     if errors.As(err, &pe) {
                            code = pe.Code // invalid_dpop_proof | use_dpop_nonce
                     }
                     a.fail(w, 401, fmt.Sprintf(`DPoP error="%s", algs="ES256"`, code))
                     return
              }
              if jkt != cl.Cnf.Jkt {
                     a.fail(w, 401, `DPoP error="invalid_token", algs="ES256"`)
                     return
              }
              // The device must be active AND still bound to this DPoP key (Ch 15: one device, one key).
              if !a.Devices.Active(cl.Sub, cl.DeviceID, jkt) {
                     a.fail(w, 401, `DPoP error="invalid_token", error_description="device revoked"`)
                     return
              }
              if !slices.Contains(cl.scopes, scope) {
                     w.Header().Set("WWW-Authenticate", fmt.Sprintf(`DPoP error="insufficient_scope", scope="%s"`, scope))
                     writeErr(w, 403, "FORBIDDEN", false)
                     return
              }
              if stepUpScopes[scope] && !(cl.Acr == "phr" && now.Sub(time.Unix(cl.AuthTime, 0)) <= 5*time.Minute) {
                     // RFC 9470: the client re-authorizes with acr_values=phr and max_age=300 (Ch 12 §12.8, Ch 14).
                     w.Header().Set("WWW-Authenticate",
                            `DPoP error="insufficient_user_authentication", acr_values="phr", max_age=300`)
                     writeErr(w, 401, "STEP_UP_REQUIRED", false)
                     return
              }
              caller := &Caller{Account: cl.Sub, Device: cl.DeviceID, Claims: cl}
              if slot, ok := r.Context().Value(slotKey{}).(*Caller); ok {
                     *slot = *caller // lets the access log (Listing 27.12) see who called, after the fact
              }
              ctx := context.WithValue(r.Context(), ctxKey{}, caller)
              next(w, r.WithContext(ctx))
       }
}

// Scopes that need acr=phr with auth_time ≤ 5 minutes (Ch 13, 15, 20).
var stepUpScopes = map[string]bool{"devices:enroll": true, "keys:write": true, "devices:revoke": true}

// writeErr emits the spec's Error message (Listing 26.1), JSON-framed. Status codes follow the
// code, and "detail" never carries anything an attacker could use as an oracle.
func writeErr(w http.ResponseWriter, status int, code string, retryable bool) {
       w.Header().Set("Content-Type", "application/json")
       w.WriteHeader(status)
       json.NewEncoder(w).Encode(map[string]any{"code": code, "retryable": retryable})
}
