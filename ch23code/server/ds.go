// ds.go
// Listing 23.2 — Go: MLS delivery service — commit ordering and the KeyPackage
// directory. The DS never sees plaintext or group secrets. Its
// security-relevant job is ORDER: in each epoch it accepts exactly one Commit
// and gives every member the same sequence of handshake messages. (Group ID and
// epoch are visible in MLS framing, so the DS can enforce this without
// decrypting anything.)
package main

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

type Kind int

const (
    Commit Kind = iota
    Proposal
    Application
)

type Envelope struct {
    Group  string
    Epoch  uint64 // epoch the message was created in (from the MLS header)
    Kind   Kind
    Sender string
    Wire   []byte
}

type group struct {
    epoch   uint64          // current epoch = number of accepted commits
    // device IDs that receive fan-out (from accepted commits / Welcomes)
    members map[string]bool
    log     []Envelope      // the single ordered handshake log
    queues  map[string][]Envelope
}

type DS struct {
    mu     sync.Mutex
    groups map[string]*group
    // application messages from epoch-Grace are still delivered (in-flight
    // sends)
    Grace  uint64
}

func NewDS() *DS { return &DS{groups: map[string]*group{}, Grace: 1} }

var (
    ErrStaleCommit  = errors.New(
    "409 commit for an old epoch: fetch the winning commit, process it, " +
    "rebase, retry")
    ErrFuture       = errors.New("400 message for a future epoch")
    ErrTooOld       = errors.New(
    "410 application message from an epoch too old")
    ErrUnknownGroup = errors.New("404 unknown group")
)

func (d *DS) Create(groupID, creator string) {
    d.mu.Lock()
    defer d.mu.Unlock()
    d.groups[groupID] = &group{members: map[string]bool{creator: true},
        queues: map[string][]Envelope{}}
}

// Submit implements a STRONGLY CONSISTENT DS for handshake messages: the first
// Commit for the current epoch wins; every other Commit for that epoch is
// rejected so its author rebases.
func (d *DS) Submit(e Envelope, joining, leaving []string) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    g, ok := d.groups[e.Group]
    if !ok {
        return ErrUnknownGroup
    }
    switch {
    case e.Epoch > g.epoch:
        return ErrFuture
    case e.Kind == Commit && e.Epoch < g.epoch:
        return ErrStaleCommit
    case e.Kind == Application && e.Epoch+d.Grace < g.epoch:
        return ErrTooOld
    }
    if e.Kind == Commit {
        g.log = append(g.log, e)
        g.epoch++
        // removed members get the Commit (to learn they're out), then nothing
        for _, m := range leaving {
            g.queues[m] = append(g.queues[m], e)
            delete(g.members, m)
        }
    }
    for m := range g.members {
        if m != e.Sender {
            g.queues[m] = append(g.queues[m], e)
        }
    }
    // joiners receive a Welcome out of band; fan-out starts with the next epoch
    for _, m := range joining {
        g.members[m] = true
    }
    return nil
}

func (d *DS) Fetch(groupID, member string) []Envelope {
    d.mu.Lock()
    defer d.mu.Unlock()
    g, ok := d.groups[groupID]
    if !ok {
        return nil
    }
    q := g.queues[member]
    delete(g.queues, member)
    return q
}

// ---- KeyPackage directory ----

type KeyPackage struct {
    ID         string
    LastResort bool      // reusable fallback (RFC 9420 last_resort extension)
    // KeyPackage lifetime: expired ones must never be served
    NotAfter   time.Time
}

type Directory struct {
    mu   sync.Mutex
    kps  map[string][]KeyPackage // device → one-time KeyPackages (FIFO)
    last map[string]KeyPackage   // device → last-resort KeyPackage
    Low  func(device string, left int)
}

func NewDirectory() *Directory {
    return &Directory{kps: map[string][]KeyPackage{},
        last: map[string]KeyPackage{}, Low: func(string, int) {}}
}

func (k *Directory) Upload(device string, kps ...KeyPackage) {
    k.mu.Lock()
    defer k.mu.Unlock()
    for _, kp := range kps {
        if kp.LastResort {
            k.last[device] = kp
        } else {
            k.kps[device] = append(k.kps[device], kp)
        }
    }
}

// Claim hands out one KeyPackage: a fresh one-time package if any is unexpired
// (consumed atomically, never twice), otherwise the last-resort package. Rate
// limiting as in Ch 18 §18.6.
func (k *Directory) Claim(device string, now time.Time) (KeyPackage, error) {
    k.mu.Lock()
    defer k.mu.Unlock()
    q := k.kps[device]
    for len(q) > 0 {
        kp := q[0]
        q = q[1:]
        if now.Before(kp.NotAfter) {
            k.kps[device] = q
            if len(q) < 10 {
                go k.Low(device, len(q))
            }
            return kp, nil
        } // expired: drop it and look at the next
    }
    k.kps[device] = q
    if lr, ok := k.last[device]; ok && now.Before(lr.NotAfter) {
        return lr, nil
    }
    return KeyPackage{}, fmt.Errorf("404 no valid KeyPackage for %s", device)
}
