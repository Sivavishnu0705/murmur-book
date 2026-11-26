// main.go
// Listing 11.5 — Go: lab driver. A legitimate app and a malicious app that registered the
// same custom URL scheme both receive the redirect; then a refresh race with and without
// single-flight coordination.
package main

import (
       "crypto/sha256"
       "fmt"
       "sync"
)

func pkcePair() (verifier, challenge string) {
       verifier = random() // 32 random bytes → 43-char base64url
       sum := sha256.Sum256([]byte(verifier))
       return verifier, b64.EncodeToString(sum[:])
}

func result(t *Tokens, err error) string {
       if err != nil {
              return "FAIL  " + err.Error()
       }
       return "tokens issued"
}

// RefreshCoordinator is the single-flight pattern from Listing 11.4, in Go.
type RefreshCoordinator struct {
       mu       sync.Mutex
       inflight *call
       rt       string
       as       *AuthServer
}

type call struct {
       done chan struct{}
       err  error
}

func (c *RefreshCoordinator) Refresh() error {
       c.mu.Lock()
       if c.inflight != nil { // someone is already refreshing: wait for their result
              cl := c.inflight
              c.mu.Unlock()
              <-cl.done
              return cl.err
       }
       cl := &call{done: make(chan struct{})}
       c.inflight = cl
       rt := c.rt
       c.mu.Unlock()

       t, err := c.as.Refresh(rt, "murmur-android")

       c.mu.Lock()
       if err == nil {
              c.rt = t.Refresh // store the rotated token BEFORE anyone else can refresh
       }
       cl.err = err
       c.inflight = nil
       c.mu.Unlock()
       close(cl.done)
       return err
}

func main() {
       const scheme = "example.murmur:/oauth/callback" // private-use scheme: ANY app can claim it
       fmt.Println("── Code interception via a shared custom URL scheme ──")
       for _, pkce := range []bool{false, true} {
              as := NewAuthServer()
              as.RequirePKCE = pkce
              as.clients["murmur-android"] = []string{scheme}
              v, ch := pkcePair()
              method := "S256"
              if !pkce {
                     ch, method = "", ""
              }
              code, err := as.Authorize("murmur-android", scheme, "alice", ch, method)
              if err != nil {
                     panic(err)
              }
              // The OS delivers the redirect to the MALICIOUS app (it registered the same scheme).
              attacker := result(as.ExchangeCode(code, "murmur-android", scheme, ""))
              fmt.Printf("PKCE enforced=%-5v  attacker redeems intercepted code:   %s\n", pkce, attacker)
              // The legitimate app tries too (if it ever got the code).
              fmt.Printf("PKCE enforced=%-5v  legitimate app redeems afterwards:   %s\n", pkce,
                     result(as.ExchangeCode(code, "murmur-android", scheme, v)))
       }

       fmt.Println("\n── PKCE edge cases (enforced) ──")
       as := NewAuthServer()
       as.clients["murmur-android"] = []string{"https://app.murmur.example/oauth/callback"}
       redirect := "https://app.murmur.example/oauth/callback"
       _, ch := pkcePair()
       _, err := as.Authorize("murmur-android", redirect, "alice", ch, "plain")
       fmt.Printf("%-52s %v\n", "code_challenge_method=plain", err)
       _, err = as.Authorize("murmur-android", "https://app.murmur.example/oauth/callback/../evil", "alice", ch, "S256")
       fmt.Printf("%-52s %v\n", "redirect_uri not exactly registered", err)
       v, ch := pkcePair()
       code, _ := as.Authorize("murmur-android", redirect, "alice", ch, "S256")
       _, wrong := pkcePair()
       fmt.Printf("%-52s %s\n", "attacker's own verifier for the victim's code", result(as.ExchangeCode(code, "murmur-android", redirect, wrong)))
       fmt.Printf("%-52s %s\n", "victim retries with correct verifier (code burned)", result(as.ExchangeCode(code, "murmur-android", redirect, v)))
       v, ch = pkcePair()
       code, _ = as.Authorize("murmur-android", redirect, "alice", ch, "S256")
       first, err := as.ExchangeCode(code, "murmur-android", redirect, v)
       fmt.Printf("%-52s %s\n", "legitimate redemption", result(first, err))
       fmt.Printf("%-52s %s\n", "same code redeemed again (replay)", result(as.ExchangeCode(code, "murmur-android", redirect, v)))
       _, err = as.Refresh(first.Refresh, "murmur-android")
       fmt.Printf("%-52s %s\n", "  → tokens from the first redemption still usable?", result(nil, err))

       fmt.Println("\n── Refresh race: 5 requests get 401 at once and all refresh ──")
       for _, single := range []bool{false, true} {
              as := NewAuthServer()
              as.clients["murmur-android"] = []string{redirect}
              v, ch := pkcePair()
              code, _ := as.Authorize("murmur-android", redirect, "alice", ch, "S256")
              t, _ := as.ExchangeCode(code, "murmur-android", redirect, v)
              var wg sync.WaitGroup
              var mu sync.Mutex
              ok, failed := 0, 0
              coord := &RefreshCoordinator{rt: t.Refresh, as: as}
              start := make(chan struct{})
              for i := 0; i < 5; i++ {
                     wg.Add(1)
                     go func() {
                            defer wg.Done()
                            <-start
                            var err error
                            if single {
                                   err = coord.Refresh()
                            } else {
                                   _, err = as.Refresh(t.Refresh, "murmur-android") // each request uses the token it read
                            }
                            mu.Lock()
                            if err == nil {
                                   ok++
                            } else {
                                   failed++
                            }
                            mu.Unlock()
                     }()
              }
              close(start)
              wg.Wait()
              latest := t.Refresh
              if single {
                     latest = coord.rt
              }
              fmt.Printf("single-flight=%-5v  succeeded=%d failed=%d  session revoked=%v\n",
                     single, ok, failed, as.FamilyRevoked(latest))
       }
}
