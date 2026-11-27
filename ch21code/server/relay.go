// relay.go
// Listing 21.1 — Go: murmur-relay accepting sealed envelopes with
// delivery-token checks. A sealed send is UNAUTHENTICATED: the relay learns the
// recipient, not the sender. To stop strangers from spamming anyone, the sender
// must present the recipient's delivery token, which only the recipient's
// contacts know (it is derived from a key shared inside E2EE profile data). The
// relay stores only a hash of each recipient's token.
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
    "errors"
    "fmt"
    "sync"
    "time"
)

// DeliveryToken is computed by the recipient and by contacts who know its
// access key.
func DeliveryToken(accessKey []byte) []byte {
    m := hmac.New(sha256.New, accessKey)
    m.Write([]byte("murmur delivery token v1"))
    return m.Sum(nil)
}

type Relay struct {
    mu        sync.Mutex
    tokenHash map[string][32]byte // recipient account → SHA-256(delivery token)
    queues    map[string][][]byte // recipient device → envelopes
    limiter   map[string][]time.Time
    Log       []string // what an operator, a breach or a subpoena would see
    PerMinute int
}

func NewRelay() *Relay {
    return &Relay{tokenHash: map[string][32]byte{},
        queues: map[string][][]byte{},
        limiter: map[string][]time.Time{}, PerMinute: 60}
}

// RegisterToken: the recipient's own authenticated device sets (or rotates) its
// token hash.
func (r *Relay) RegisterToken(account string, token []byte) {
    r.mu.Lock()
    r.tokenHash[account] = sha256.Sum256(token)
    r.mu.Unlock()
}

var (
    ErrToken = errors.New("401 delivery token invalid")
    ErrRate  = errors.New("429 rate limited")
)

// SendSealed: no sender authentication. Checks: delivery token, rate limit per
// (recipient, client IP), envelope size cap. Logs: recipient, size bucket,
// minute, IP — no sender.
func (r *Relay) SendSealed(recipientAccount, recipientDevice string, token,
    envelope []byte, ip string, now time.Time) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    want, ok := r.tokenHash[recipientAccount]
    got := sha256.Sum256(token)
    if !ok || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
        r.Log = append(r.Log,
            fmt.Sprintf("%s REJECT sealed → %s (bad token) ip=%s",
            now.Format("15:04"), recipientDevice, ip))
        return ErrToken
    }
    key := recipientAccount + "|" + ip
    var recent []time.Time
    for _, t := range r.limiter[key] {
        if now.Sub(t) < time.Minute {
            recent = append(recent, t)
        }
    }
    if len(recent) >= r.PerMinute {
        return ErrRate
    }
    r.limiter[key] = append(recent, now)
    if len(envelope) > 256*1024 {
        return errors.New(
            "413 envelope too large (attachments go to the CDN, §21.5)")
    }
    r.queues[recipientDevice] = append(r.queues[recipientDevice], envelope)
    r.Log = append(r.Log, fmt.Sprintf("%s sealed → %s %dB ip=%s",
        now.Format("15:04"), recipientDevice, len(envelope), ip))
    return nil
}

// SendIdentified: the traditional path, authenticated with the sender's session
// (Ch 15). Used when the sender does not have the recipient's delivery token
// (first contact, strangers).
func (r *Relay) SendIdentified(senderDevice, recipientDevice string,
    envelope []byte, ip string, now time.Time) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.queues[recipientDevice] = append(r.queues[recipientDevice], envelope)
    r.Log = append(r.Log, fmt.Sprintf("%s %s → %s %dB ip=%s",
        now.Format("15:04"), senderDevice, recipientDevice, len(envelope), ip))
}

func (r *Relay) Drain(device string) [][]byte {
    r.mu.Lock()
    defer r.mu.Unlock()
    q := r.queues[device]
    delete(r.queues, device)
    return q
}

// ---- push (§21.4): the relay asks APNs/FCM to wake the device; what it sends
// is the question ----

type PushProvider struct{ Seen []string } // what Apple/Google could log

func (p *PushProvider) Deliver(deviceToken string, payload string,
    now time.Time) {
    p.Seen = append(p.Seen, fmt.Sprintf("%s token=%s payload=%s",
        now.Format("15:04"), deviceToken, payload))
}
