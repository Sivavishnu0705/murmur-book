// attach.go
// Listing 27.9 — Go: the attachment store's two security jobs: authorize uploads with short-lived,
// size-exact signed URLs, and keep blobs only for the retention period. It never sees a key:
// clients encrypt with STREAM before upload (Ch 21 §21.5) and send the key inside the message.
package main

import (
       "crypto/hmac"
       "crypto/rand"
       "crypto/sha256"
       "encoding/hex"
       "encoding/json"
       "fmt"
       "io"
       "net/http"
       "strconv"
       "sync"
       "time"
)

const (
       maxAttachment = 100 << 20
       urlLifetime   = 5 * time.Minute
       retention     = 30 * 24 * time.Hour
)

type AttachmentStore struct {
       Key   []byte // HMAC key shared by murmur-api (signs) and the CDN origin (verifies)
       Base  string // public URL of the CDN origin
       Clock func() time.Time
       mu    sync.Mutex
       blobs map[string]blob
}

type blob struct {
       data    []byte
       created time.Time
}

func (s *AttachmentStore) sign(method, id string, size int64, exp int64) string {
       m := hmac.New(sha256.New, s.Key)
       fmt.Fprintf(m, "murmur/v1/attachment-url\x00%s\x00%s\x00%d\x00%d", method, id, size, exp)
       return hex.EncodeToString(m.Sum(nil))
}

// POST /v1/attachments  (scope attachments:write) → {cdn_id, upload_url}
func (s *AttachmentStore) Authorize(w http.ResponseWriter, r *http.Request) {
       var q struct{ Size int64 }
       if !readJSON(w, r, 1<<10, &q) || q.Size <= 0 || q.Size > maxAttachment {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       idb := make([]byte, 16)
       rand.Read(idb)
       id := hex.EncodeToString(idb) // unguessable; carries nothing about sender or recipient
       exp := s.Clock().Add(urlLifetime).Unix()
       u := fmt.Sprintf("%s/cdn/%s?size=%d&exp=%d&sig=%s", s.Base, id, q.Size, exp, s.sign("PUT", id, q.Size, exp))
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(map[string]string{"cdn_id": id, "upload_url": u})
}

// PUT /cdn/{id}?size&exp&sig — the CDN origin. The body must be exactly `size` bytes.
func (s *AttachmentStore) Upload(w http.ResponseWriter, r *http.Request) {
       id := r.PathValue("id")
       size, _ := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
       exp, _ := strconv.ParseInt(r.URL.Query().Get("exp"), 10, 64)
       want := s.sign("PUT", id, size, exp)
       if !hmac.Equal([]byte(want), []byte(r.URL.Query().Get("sig"))) || s.Clock().Unix() > exp {
              writeErr(w, 403, "FORBIDDEN", false)
              return
       }
       if r.ContentLength != size {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       data, err := io.ReadAll(io.LimitReader(r.Body, size+1))
       if err != nil || int64(len(data)) != size {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       s.mu.Lock()
       defer s.mu.Unlock()
       if _, exists := s.blobs[id]; exists { // a signed URL uploads once; no overwrite
              writeErr(w, 409, "CONFLICT", false)
              return
       }
       s.blobs[id] = blob{data, s.Clock()}
       w.WriteHeader(201)
}

// GET /cdn/{id} — download by unguessable ID (the pointer is inside the E2EE message).
func (s *AttachmentStore) Download(w http.ResponseWriter, r *http.Request) {
       s.mu.Lock()
       b, ok := s.blobs[r.PathValue("id")]
       s.mu.Unlock()
       if !ok || s.Clock().Sub(b.created) > retention {
              writeErr(w, 404, "NOT_FOUND", false)
              return
       }
       w.Write(b.data)
}

// Sweep deletes expired blobs; run hourly.
func (s *AttachmentStore) Sweep() int {
       s.mu.Lock()
       defer s.mu.Unlock()
       n := 0
       for id, b := range s.blobs {
              if s.Clock().Sub(b.created) > retention {
                     delete(s.blobs, id)
                     n++
              }
       }
       return n
}
