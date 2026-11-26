// Listing 7.2 — Go: RFC 8470 "425 Too Early" and idempotency keys for state-changing requests.
package main

import (
       "net/http"
       "net/http/httptest"
       "sync"
       "time"
)

// RejectEarlyUnsafe implements RFC 8470 at the application tier. A TLS terminator that
// accepts 0-RTT marks requests that arrived in early data with "Early-Data: 1". Only
// safe, idempotent methods may be processed from early data; anything else gets 425,
// and the client retries after the handshake completes (replay-protected).
func RejectEarlyUnsafe(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
              if r.Header.Get("Early-Data") == "1" && !safeMethod(r.Method) {
                     http.Error(w, "too early", http.StatusTooEarly) // 425
                     return
              }
              next.ServeHTTP(w, r)
       })
}

func safeMethod(m string) bool {
       return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Idempotency makes a state-changing request safe to receive twice, whatever the cause:
// 0-RTT replay, a mobile retry after a dropped connection, or a user double-tap.
// The client generates a random key per logical operation and sends it on every retry.
type Idempotency struct {
       mu   sync.Mutex
       seen map[string]entry // in production: a shared store with TTL (e.g. Redis), scoped per user
       ttl  time.Duration
}

type entry struct {
       status int
       body   []byte
       at     time.Time
}

func NewIdempotency(ttl time.Duration) *Idempotency {
       return &Idempotency{seen: map[string]entry{}, ttl: ttl}
}

func (i *Idempotency) Wrap(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
              if safeMethod(r.Method) {
                     next.ServeHTTP(w, r)
                     return
              }
              key := r.Header.Get("Idempotency-Key")
              if key == "" {
                     http.Error(w, "Idempotency-Key required", http.StatusBadRequest)
                     return
              }
              // Teaching simplification: ONE lock held across execution serializes every
              // state-changing request (not just duplicates). Production: see the note below.
              i.mu.Lock()
              defer i.mu.Unlock()
              if e, ok := i.seen[key]; ok && time.Since(e.at) < i.ttl {
                     w.Header().Set("Idempotent-Replay", "true")
                     w.WriteHeader(e.status)
                     w.Write(e.body)
                     return
              }
              rec := httptest.NewRecorder()
              next.ServeHTTP(rec, r)
              i.seen[key] = entry{rec.Code, rec.Body.Bytes(), time.Now()}
              for k, v := range rec.Header() {
                     w.Header()[k] = v
              }
              w.WriteHeader(rec.Code)
              w.Write(rec.Body.Bytes())
       })
}
