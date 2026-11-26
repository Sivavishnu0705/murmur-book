// relay.go
// Listing 27.7 — Go: the relay — per-device queues with acknowledgement-based deletion.
// Delivery is at-least-once: an envelope stays queued until the RECIPIENT DEVICE acknowledges
// it (after decrypting and persisting, Ch 19 §19.9), and is deleted then. Senders must address
// every active device of the recipient account, or the relay refuses with the current set
// (Ch 20 fan-out). Sealed-sender deliveries carry a delivery token instead of a sender identity.
package main

import (
       "crypto/rand"
       "crypto/sha256"
       "crypto/subtle"
       "encoding/base64"
       "encoding/json"
       "net/http"
       "slices"
       "sort"
       "sync"
       "time"
)

const (
       maxEnvelope = 256 << 10           // attachments go to the attachment store, not the relay
       envelopeTTL = 30 * 24 * time.Hour // offline storage limit; then the sender's client shows "not delivered"
       fetchBatch  = 100
)

type Relay struct {
       Queues   QueueStore
       Devices  *Registry
       Wake     func(device string) // push gateway (Listing 27.10): content-free, collapsed
       mu       sync.Mutex
       tokens   map[string][32]byte // account → SHA-256(delivery token) (Ch 21 §21.2)
       byAcct   func(account string) []string
       IPLimits *Limiter // sealed sends are unauthenticated: limit per source address
}

type outgoing struct {
       Device string `json:"device"`
       Body   []byte `json:"body"` // Envelope protobuf (Listing 26.1), opaque here
}

type sendReq struct {
       RecipientAccount string     `json:"recipient_account"`
       Envelopes        []outgoing `json:"envelopes"`
}

// activeDevices lists the account's non-revoked devices, minus one (the sender's own).
func (rl *Relay) activeDevices(account, except string) []string {
       var out []string
       for _, d := range rl.byAcct(account) {
              if dev, ok := rl.Devices.Get(d); ok && dev.RevokedAt.IsZero() && d != except {
                     out = append(out, d)
              }
       }
       sort.Strings(out)
       return out
}

// deliver checks the device set, then enqueues every envelope or none.
func (rl *Relay) deliver(w http.ResponseWriter, r *http.Request, q sendReq, senderDevice string) {
       want := rl.activeDevices(q.RecipientAccount, senderDevice)
       var got []string
       for _, e := range q.Envelopes {
              if len(e.Body) == 0 || len(e.Body) > maxEnvelope {
                     writeErr(w, 400, "MALFORMED", false)
                     return
              }
              got = append(got, e.Device)
       }
       sort.Strings(got)
       if len(want) == 0 {
              writeErr(w, 404, "NOT_FOUND", false)
              return
       }
       if !slices.Equal(want, got) {
              // 409 with the current device set: the client fetches the signed device list, verifies
              // it (Ch 20), starts sessions with new devices and retries. The relay never "fills in".
              w.Header().Set("Content-Type", "application/json")
              w.WriteHeader(409)
              json.NewEncoder(w).Encode(map[string]any{"code": "DEVICE_MISMATCH", "retryable": true, "devices": want})
              return
       }
       batch := make([]Item, len(q.Envelopes))
       for i, e := range q.Envelopes {
              guid := make([]byte, 16)
              rand.Read(guid)
              batch[i] = Item{Device: e.Device, GUID: guid, Body: e.Body}
       }
       // All devices or none: a full quota on one device must not deliver to the others.
       if err := rl.Queues.EnqueueBatch(r.Context(), batch, envelopeTTL); err == ErrQueueFull {
              writeErr(w, 507, "RATE_LIMITED", true)
              return
       } else if err != nil {
              writeErr(w, 503, "UNAVAILABLE", true)
              return
       }
       for _, e := range q.Envelopes {
              rl.Wake(e.Device)
       }
       w.WriteHeader(202)
}

// POST /v1/messages  (scope messages:send) — identified sender (first contact, own devices).
func (rl *Relay) Send(w http.ResponseWriter, r *http.Request) {
       var q sendReq
       if readJSON(w, r, 4*maxEnvelope, &q) {
              rl.deliver(w, r, q, CallerFrom(r).Device)
       }
}

// POST /v1/sealed  — NO Authorization header: the relay must not learn who sends. Access is
// the recipient-chosen delivery token, compared in constant time; abuse is limited per IP.
func (rl *Relay) SendSealed(w http.ResponseWriter, r *http.Request) {
       if !rl.IPLimits.Allow(r.RemoteAddr, time.Now()) {
              writeErr(w, 429, "RATE_LIMITED", true)
              return
       }
       var q sendReq
       if !readJSON(w, r, 4*maxEnvelope, &q) {
              return
       }
       raw, err := base64.StdEncoding.DecodeString(r.Header.Get("Murmur-Delivery-Token"))
       if err != nil || len(raw) < 16 {
              writeErr(w, 401, "UNAUTHENTICATED", false) // same answer as a wrong token
              return
       }
       tok := sha256.Sum256(raw)
       rl.mu.Lock()
       want, ok := rl.tokens[q.RecipientAccount]
       rl.mu.Unlock()
       if !ok || subtle.ConstantTimeCompare(tok[:], want[:]) != 1 {
              writeErr(w, 401, "UNAUTHENTICATED", false) // same answer for "no such account"
              return
       }
       rl.deliver(w, r, q, "")
}

// PUT /v1/delivery-token  (scope messages:read): the recipient sets its token (Ch 21).
func (rl *Relay) SetDeliveryToken(w http.ResponseWriter, r *http.Request) {
       var q struct {
              Token []byte `json:"token"`
       }
       if !readJSON(w, r, 1<<10, &q) || len(q.Token) < 16 {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       rl.mu.Lock()
       rl.tokens[CallerFrom(r).Account] = sha256.Sum256(q.Token)
       rl.mu.Unlock()
       w.WriteHeader(204)
}

// GET /v1/messages  (scope messages:read) — the caller's queue, oldest first. Nothing is
// deleted here: a crash between fetch and persist must cause a redelivery, not a loss.
func (rl *Relay) Fetch(w http.ResponseWriter, r *http.Request) {
       msgs, err := rl.Queues.Fetch(r.Context(), CallerFrom(r).Device, fetchBatch)
       if err != nil {
              writeErr(w, 503, "UNAVAILABLE", true)
              return
       }
       if msgs == nil {
              msgs = []Stored{}
       }
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(map[string]any{"envelopes": msgs})
}

// POST /v1/messages/ack  (scope messages:read) — delete acknowledged envelopes. The store
// scopes the delete to the caller's device, so a guessed or stolen GUID deletes nothing.
func (rl *Relay) Ack(w http.ResponseWriter, r *http.Request) {
       var q struct {
              GUIDs [][]byte `json:"guids"`
       }
       if !readJSON(w, r, 64<<10, &q) || len(q.GUIDs) > fetchBatch {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       n, err := rl.Queues.Ack(r.Context(), CallerFrom(r).Device, q.GUIDs)
       if err != nil {
              writeErr(w, 503, "UNAVAILABLE", true)
              return
       }
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(map[string]int{"deleted": n})
}
