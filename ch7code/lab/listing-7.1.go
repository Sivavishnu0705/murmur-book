// Listing 7.1 — Go: session tickets with rotating ticket keys (and why 0-RTT is
// absent).
package main

import (
    "crypto/rand"
    "crypto/tls"
    "sync"
    "time"
)

// TicketKeyRing holds the ticket-encryption keys shared by every server in a
// fleet. keys[0] encrypts new tickets; all keys can decrypt, so tickets survive
// one rotation. Rotating and DELETING old keys is what bounds how long a stolen
// ticket key can decrypt recorded resumption handshakes (ticket keys are a
// forward-secrecy weak point).
type TicketKeyRing struct {
    mu   sync.Mutex
    keys [][32]byte
    keep int // how many old keys to keep for decryption
}

func NewTicketKeyRing(keep int) *TicketKeyRing {
    r := &TicketKeyRing{keep: keep}
    r.Rotate()
    return r
}

func (r *TicketKeyRing) Rotate() {
    var k [32]byte
    if _, err := rand.Read(k[:]); err != nil {
        panic(err)
    }
    r.mu.Lock()
    defer r.mu.Unlock()
    r.keys = append([][32]byte{k}, r.keys...)
    if len(r.keys) > r.keep {
        for i := r.keep; i < len(r.keys); i++ {
            r.keys[i] = [32]byte{} // best-effort wipe of retired keys
        }
        r.keys = r.keys[:r.keep]
    }
}

func (r *TicketKeyRing) Apply(cfg *tls.Config) {
    r.mu.Lock()
    defer r.mu.Unlock()
    cfg.SetSessionTicketKeys(r.keys) // first key encrypts; all decrypt
}

// ServerConfig: TLS 1.3 only, tickets on, keys rotated hourly, 3 keys retained.
// Go's crypto/tls never accepts 0-RTT early data on TCP connections, so this
// server supports resumption (with a fresh ECDHE exchange, psk_dhe_ke) but not
// 0-RTT.
func ServerConfig(cert tls.Certificate, ring *TicketKeyRing) *tls.Config {
    cfg := &tls.Config{
        MinVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{cert},
    }
    ring.Apply(cfg)
    go func() {
        for range time.Tick(time.Hour) {
            ring.Rotate()
            ring.Apply(cfg)
        }
    }()
    return cfg
}
