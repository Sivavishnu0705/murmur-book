// main.go
// Listing 13.5 — Go: lab driver. "Make stolen tokens worthless": bearer replay, then DPoP-bound
// tokens attacked with stolen tokens and stolen proofs, server nonces, and refresh-token theft.
package main

import (
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/sha256"
       "encoding/json"
       "fmt"
       "io"
       "net/http"
       "net/http/httptest"
       "strings"
       "time"
)

// device holds a P-256 key: in the app, a non-exportable Keystore/Secure Enclave key.
type device struct{ k *ecdsa.PrivateKey }

func newDevice() device { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return device{k} }

func (d device) jwk() JWK {
       return JWK{Kty: "EC", Crv: "P-256",
              X: b64.EncodeToString(d.k.X.FillBytes(make([]byte, 32))),
              Y: b64.EncodeToString(d.k.Y.FillBytes(make([]byte, 32)))}
}

func (d device) proof(method, htu, accessToken, nonce string, iat time.Time) string {
       h, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": d.jwk()})
       jti := make([]byte, 16)
       rand.Read(jti)
       c := map[string]any{"jti": b64.EncodeToString(jti), "htm": method, "htu": htu, "iat": iat.Unix()}
       if accessToken != "" {
              a := sha256.Sum256([]byte(accessToken))
              c["ath"] = b64.EncodeToString(a[:])
       }
       if nonce != "" {
              c["nonce"] = nonce
       }
       cb, _ := json.Marshal(c)
       in := b64.EncodeToString(h) + "." + b64.EncodeToString(cb)
       dg := sha256.Sum256([]byte(in))
       r, s, _ := ecdsa.Sign(rand.Reader, d.k, dg[:])
       sig := make([]byte, 64)
       r.FillBytes(sig[:32])
       s.FillBytes(sig[32:])
       return in + "." + b64.EncodeToString(sig)
}

const origin = "https://api.murmur.example" // what the app sees; the test server sits "behind the CDN"

func main() {
       now := time.Now()
       clock := func() time.Time { return now }
       db := &tokenDB{m: map[string]*AccessToken{}}
       v := &Verifier{Window: 60 * time.Second, Replay: NewReplayCache(), PublicOrigin: origin}
       ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "200 messages for alice") })
       srv := httptest.NewServer(v.Middleware(db.get, clock, ok))
       defer srv.Close()

       send := func(label, method, path, authz string, proofs ...string) *http.Response {
              req, _ := http.NewRequest(method, srv.URL+path, nil)
              req.Header.Set("Authorization", authz)
              for _, p := range proofs {
                     req.Header.Add("DPoP", p)
              }
              resp, err := http.DefaultClient.Do(req)
              if err != nil {
                     panic(err)
              }
              body, _ := io.ReadAll(resp.Body)
              resp.Body.Close()
              out := strings.TrimSpace(string(body))
              if resp.StatusCode == 200 {
                     out = "200 OK"
              } else {
                     out = "401  " + out
              }
              fmt.Printf("  %-50s %s\n", label, out)
              return resp
       }

       ex := JWK{Kty: "EC", Crv: "P-256", X: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
              Y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"} // the example key in RFC 9449
       fmt.Println("── 0. RFC 7638 thumbprint of RFC 9449's example key ──")
       fmt.Printf("  jkt = %s  match=%v\n", ex.Thumbprint(), ex.Thumbprint() == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")

       fmt.Println("── 1. Bearer token copied from a log line ──")
       db.put("bearer-AT-1", AccessToken{Sub: "alice", Exp: now.Add(5 * time.Minute)})
       logLine := `D/OkHttp: Authorization: Bearer bearer-AT-1`
       stolen := strings.TrimPrefix(logLine, "D/OkHttp: Authorization: Bearer ")
       send("attacker replays the bearer token", "GET", "/v1/messages", "Bearer "+stolen)

       fmt.Println("── 2. DPoP-bound token (cnf.jkt = device key) ──")
       alice, mallory := newDevice(), newDevice()
       at := "dpop-AT-1"
       db.put(at, AccessToken{Sub: "alice", Jkt: alice.jwk().Thumbprint(), Exp: now.Add(5 * time.Minute)})
       p1 := alice.proof("GET", origin+"/v1/messages", at, "", now)
       send("Alice's app: token + fresh proof", "GET", "/v1/messages", "DPoP "+at, p1)
       send("attacker: stolen token as Bearer, no proof", "GET", "/v1/messages", "Bearer "+at)
       send("attacker: stolen token, proof from own key", "GET", "/v1/messages", "DPoP "+at,
              mallory.proof("GET", origin+"/v1/messages", at, "", now))

       fmt.Println("── 3. Attacker steals the token AND proofs (proxy, logs, crash report) ──")
       send("replay the captured proof verbatim", "GET", "/v1/messages", "DPoP "+at, p1)
       unused := alice.proof("GET", origin+"/v1/messages", at, "", now) // captured, never sent
       send("captured proof, different URL", "GET", "/v1/devices", "DPoP "+at, unused)
       send("captured proof, different method", "POST", "/v1/messages", "DPoP "+at, unused)
       now = now.Add(5 * time.Minute)
       db.put("dpop-AT-2", AccessToken{Sub: "alice", Jkt: alice.jwk().Thumbprint(), Exp: now.Add(5 * time.Minute)})
       send("unused captured proof, 5 minutes later", "GET", "/v1/messages", "DPoP dpop-AT-2", unused)
       fresh := alice.proof("GET", origin+"/v1/messages", at, "", now) // ath = hash of the OLD token
       send("fresh proof for old token, with new token", "GET", "/v1/messages", "DPoP dpop-AT-2", fresh)

       fmt.Println("── 4. Server nonces defeat proofs generated in advance ──")
       v.Nonces = &Nonces{}
       v.Nonces.Rotate()
       early := alice.proof("GET", origin+"/v1/messages", "dpop-AT-2", v.Nonces.Current(), now) // malware pre-signs
       r := send("app's first request, no nonce", "GET", "/v1/messages", "DPoP dpop-AT-2",
              alice.proof("GET", origin+"/v1/messages", "dpop-AT-2", "", now))
       n := r.Header.Get("DPoP-Nonce")
       send("retry with the DPoP-Nonce from the 401", "GET", "/v1/messages", "DPoP dpop-AT-2",
              alice.proof("GET", origin+"/v1/messages", "dpop-AT-2", n, now))
       v.Nonces.Rotate()
       v.Nonces.Rotate() // e.g. every few minutes
       send("pre-signed proof used after 2 nonce rotations", "GET", "/v1/messages", "DPoP dpop-AT-2", early)
       v.Nonces = nil

       fmt.Println("── 5. Refresh tokens: DPoP-bound, rotated, reuse-detected ──")
       rs := NewRefreshService()
       var events []string
       rs.Events = func(e string) { events = append(events, e) }
       iss := rs.StartFamily("alice", alice.jwk().Thumbprint(), now)
       rt1 := iss.RT
       try := func(label, rt, jkt string, t time.Time) Issued {
              out, err := rs.Refresh(rt, jkt, t)
              if err != nil {
                     fmt.Printf("  %-50s %v\n", label, err)
              } else {
                     fmt.Printf("  %-50s new tokens (RT rotated)\n", label)
              }
              for _, e := range events {
                     fmt.Printf("  %-50s   └ security event: %s\n", "", e)
              }
              events = nil
              return out
       }
       iss2 := try("Alice refreshes with her device key", rt1, alice.jwk().Thumbprint(), now)
       try("attacker: stolen current RT, own key", iss2.RT, mallory.jwk().Thumbprint(), now)
       iss3 := try("Alice refreshes again (family intact?)", iss2.RT, alice.jwk().Thumbprint(), now)
       try("malware on Alice's phone replays old RT, her key", rt1, alice.jwk().Thumbprint(), now)
       try("Alice's newest RT, after the revocation", iss3.RT, alice.jwk().Thumbprint(), now)

       bob := newDevice()
       cur := rs.StartFamily("bob", bob.jwk().Thumbprint(), now).RT
       day := 1
       for ; day <= 120; day++ { // Bob opens the app every day; each refresh rotates
              next, err := rs.Refresh(cur, bob.jwk().Thumbprint(), now.Add(time.Duration(day)*24*time.Hour))
              if err != nil {
                     break
              }
              cur = next.RT
       }
       fmt.Printf("  %-50s day %d: invalid_grant (absolute lifetime) → sign in again\n", "Bob refreshes daily from day 1", day)
}
