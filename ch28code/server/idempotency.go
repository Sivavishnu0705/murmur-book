// idempotency.go
// Listing 28.14 — Go: server side of idempotency keys (added in Chapter 28). A client sends
// `Idempotency-Key: <uuid>` on every state-changing request and REUSES it on retries. The
// first response for (device, key) is stored for 24 hours; a retry gets the stored response
// without the handler running again. The same key with a different body is refused.
package main

import (
       "bytes"
       "crypto/sha256"
       "io"
       "net/http"
       "sync"
       "time"
)

type savedResponse struct {
       bodyHash [32]byte
       status   int
       header   http.Header
       body     []byte
       at       time.Time
       done     chan struct{} // closed when the first request finishes
}

type Idempotency struct {
       mu    sync.Mutex
       saved map[string]*savedResponse
       Clock func() time.Time
       TTL   time.Duration
}

type recordingWriter struct {
       http.ResponseWriter
       status int
       buf    bytes.Buffer
}

func (w *recordingWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }
func (w *recordingWriter) Write(b []byte) (int, error) {
       w.buf.Write(b)
       return w.ResponseWriter.Write(b)
}

// Wrap must run INSIDE Authenticator.Require: the key is scoped to the authenticated device,
// so one device can never replay, or block, another device's keys.
func (ix *Idempotency) Wrap(next http.HandlerFunc) http.HandlerFunc {
       return func(w http.ResponseWriter, r *http.Request) {
              key := r.Header.Get("Idempotency-Key")
              if key == "" || len(key) > 64 {
                     writeErr(w, 400, "MALFORMED", false) // mandatory on these routes: retries must be safe
                     return
              }
              body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
              if err != nil {
                     writeErr(w, 400, "MALFORMED", false)
                     return
              }
              r.Body = io.NopCloser(bytes.NewReader(body))
              h := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\x00"), body...))
              id := CallerFrom(r).Device + "|" + key
              now := ix.Clock()

              ix.mu.Lock()
              for k, s := range ix.saved { // expiry (production: a TTL index in the database)
                     if now.Sub(s.at) > ix.TTL {
                            delete(ix.saved, k)
                     }
              }
              prev, seen := ix.saved[id]
              if !seen {
                     prev = &savedResponse{bodyHash: h, at: now, done: make(chan struct{})}
                     ix.saved[id] = prev
              }
              ix.mu.Unlock()

              if seen {
                     <-prev.done // a concurrent duplicate waits for the first one to finish
                     if prev.bodyHash != h {
                            writeErr(w, 422, "CONFLICT", false) // same key, different request: a client bug
                            return
                     }
                     for k, v := range prev.header {
                            w.Header()[k] = v
                     }
                     w.Header().Set("Idempotent-Replayed", "true")
                     w.WriteHeader(prev.status)
                     w.Write(prev.body)
                     return
              }
              rw := &recordingWriter{ResponseWriter: w, status: 200}
              next(rw, r)
              ix.mu.Lock()
              prev.status, prev.header, prev.body = rw.status, w.Header().Clone(), rw.buf.Bytes()
              if rw.status >= 500 { // a failure is not remembered: the retry should really retry
                     delete(ix.saved, id)
              }
              ix.mu.Unlock()
              close(prev.done)
       }
}
