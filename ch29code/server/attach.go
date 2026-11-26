// attach.go
// Listing 29.8 — Go: the attachment store (Listing 27.9 plus Chapter 29's resumable uploads).
// Its two security jobs: authorize uploads with short-lived,
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
       Key     []byte // HMAC key shared by murmur-api (signs) and the CDN origin (verifies)
       Base    string // public URL of the CDN origin
       Clock   func() time.Time
       mu      sync.Mutex
       blobs   map[string]blob
       partial map[string][]byte // in-progress resumable uploads (production: the object store's multipart upload)
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

// PUT /cdn/{id}?size&exp&sig — the CDN origin, with RESUMABLE uploads (added in Chapter 29):
// each PUT carries `Content-Range: bytes <start>-<end>/<size>` and must start exactly at the
// current offset; HEAD returns `Upload-Offset` so a client that lost its connection knows where
// to continue. The upload completes, once, when the offset reaches the signed size.
func (s *AttachmentStore) authorized(w http.ResponseWriter, r *http.Request) (string, int64, bool) {
       id := r.PathValue("id")
       size, _ := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
       exp, _ := strconv.ParseInt(r.URL.Query().Get("exp"), 10, 64)
       want := s.sign("PUT", id, size, exp)
       if !hmac.Equal([]byte(want), []byte(r.URL.Query().Get("sig"))) || s.Clock().Unix() > exp {
              writeErr(w, 403, "FORBIDDEN", false)
              return "", 0, false
       }
       return id, size, true
}

func (s *AttachmentStore) Offset(w http.ResponseWriter, r *http.Request) {
       id, _, ok := s.authorized(w, r)
       if !ok {
              return
       }
       s.mu.Lock()
       defer s.mu.Unlock()
       if _, done := s.blobs[id]; done {
              writeErr(w, 409, "CONFLICT", false)
              return
       }
       w.Header().Set("Upload-Offset", strconv.Itoa(len(s.partial[id])))
       w.WriteHeader(204)
}

func (s *AttachmentStore) Upload(w http.ResponseWriter, r *http.Request) {
       id, size, ok := s.authorized(w, r)
       if !ok {
              return
       }
       var start, end, total int64
       if _, err := fmt.Sscanf(r.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total); err != nil ||
              total != size || start > end || end >= size || r.ContentLength != end-start+1 || end-start+1 > 8<<20 {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       chunk, err := io.ReadAll(io.LimitReader(r.Body, end-start+2))
       if err != nil || int64(len(chunk)) != end-start+1 {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       s.mu.Lock()
       defer s.mu.Unlock()
       if _, done := s.blobs[id]; done { // a signed URL completes once; no overwrite
              writeErr(w, 409, "CONFLICT", false)
              return
       }
       if start != int64(len(s.partial[id])) { // no gaps, no overlaps: the client asks HEAD and resumes
              w.Header().Set("Upload-Offset", strconv.Itoa(len(s.partial[id])))
              writeErr(w, 409, "CONFLICT", false)
              return
       }
       s.partial[id] = append(s.partial[id], chunk...)
       if int64(len(s.partial[id])) == size {
              s.blobs[id] = blob{s.partial[id], s.Clock()}
              delete(s.partial, id)
              w.WriteHeader(201)
              return
       }
       w.Header().Set("Upload-Offset", strconv.Itoa(len(s.partial[id])))
       w.WriteHeader(202)
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
