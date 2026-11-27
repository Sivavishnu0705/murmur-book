// refresh.go
// Listing 15.3 — Go: murmur-auth's refresh endpoint. The refresh token family
// belongs to one device; each refresh needs a DPoP proof from that device's key
// (Listing 13.3 computes proofJkt), the device must still be active in the
// registry, and attestation is re-checked when it is due or when risk signals
// ask for it. Rotation and reuse detection as in Listing 13.4.
package main

import (
    "crypto/sha256"
    "errors"
    "sync"
    "time"
)

type family struct {
    device  string
    created time.Time
    revoked bool
}
type rtRec struct {
    fam    *family
    used   bool
    issued time.Time
}

type Tokens struct {
    mu       sync.Mutex
    byHash   map[[32]byte]*rtRec
    byDevice map[string]*family
}

func NewTokens() *Tokens {
    return &Tokens{byHash: map[[32]byte]*rtRec{},
        byDevice: map[string]*family{}}
}

func (t *Tokens) RevokeDevice(dev string) {
    t.mu.Lock()
    if f := t.byDevice[dev]; f != nil {
        f.revoked = true
    }
    t.mu.Unlock()
}

func (t *Tokens) issue(f *family, now time.Time) string {
    rt := randID() + randID() + randID() + randID()
    t.byHash[sha256.Sum256([]byte(rt))] = &rtRec{fam: f, issued: now}
    return rt
}

// Start creates the device's family at enrollment and returns its first refresh
// token.
func (t *Tokens) Start(dev string, now time.Time) string {
    t.mu.Lock()
    defer t.mu.Unlock()
    f := &family{device: dev, created: now}
    t.byDevice[dev] = f
    return t.issue(f, now)
}

// Attestor re-verifies the device (Play Integrity verdict / App Attest
// assertion, Ch 9 §9.5–9.6).
type Attestor func(device string) bool

type RefreshPolicy struct {
    Idle, Absolute time.Duration // 30 d, 90 d
    // 7 d: aligned with device-certificate renewal (Ch 9)
    AttestEvery    time.Duration
    AccessTTL      time.Duration // 5 min
}

type Issued struct {
    AccessToken  AccessClaims
    RefreshToken string
}

// AccessClaims: what the RFC 9068 JWT carries for murmur-api (signing elided
// here; Ch 10).
type AccessClaims struct {
    // device_id lets resource servers apply the revocation feed
    Sub, DeviceID, Jkt string
    Exp                time.Time
}

var (
    ErrInvalidGrant   = errors.New("invalid_grant")
    ErrAttestRequired = errors.New(
    "attestation_required: device integrity check failed; session suspended")
)

type RefreshEndpoint struct {
    Tokens   *Tokens
    Registry *Registry
    Attest   Attestor
    Policy   RefreshPolicy
    // anomaly signals that force an attestation re-check (§15.8)
    Risk     func(dev string) bool
    Feed     *Feed
}

func (e *RefreshEndpoint) Refresh(rt, proofJkt, region string,
    now time.Time) (*Issued, error) {
    t := e.Tokens
    t.mu.Lock()
    rec, ok := t.byHash[sha256.Sum256([]byte(rt))]
    if !ok || rec.fam.revoked {
        t.mu.Unlock()
        return nil, ErrInvalidGrant
    }
    f := rec.fam
    dev, ok := e.Registry.Get(f.device)
    switch {
    case !ok || dev.Status != "active": // the registry is the source of truth
        f.revoked = true
        t.mu.Unlock()
        return nil, ErrInvalidGrant
    // bound to the device key; refuse, don't revoke (Ch 13 §13.8)
    case proofJkt != dev.Jkt:
        t.mu.Unlock()
        e.Feed.Notify(
            "security event: refresh with wrong DPoP key for " + dev.ID)
        return nil, ErrInvalidGrant
    case rec.used: // reuse → two holders → revoke the device's session
        t.mu.Unlock()
        e.Feed.Notify("security event: refresh token reuse on " + dev.ID)
        e.Registry.revoke(dev, "murmur-auth", "refresh token reuse", now)
        return nil, ErrInvalidGrant
    case now.Sub(f.created) > e.Policy.Absolute || now.Sub(
        rec.issued) > e.Policy.Idle:
        f.revoked = true
        t.mu.Unlock()
        return nil, ErrInvalidGrant
    }
    t.mu.Unlock()

    // Attestation re-check: periodic, or forced by risk signals. Done outside
    // the token lock (it calls Google/Apple), and BEFORE the old refresh token
    // is consumed, so a transient failure doesn't strand the client with a used
    // token.
    if now.Sub(dev.AttestedAt) > e.Policy.AttestEvery || (
        e.Risk != nil && e.Risk(dev.ID)) {
        if !e.Attest(dev.ID) {
            e.Feed.Notify(
                "security event: attestation failed at refresh for " + dev.ID)
            // session suspended, not revoked: user can fix and retry
            return nil, ErrAttestRequired
        }
        dev.AttestedAt = now
    }

    t.mu.Lock()
    defer t.mu.Unlock()
    // lost a race with a concurrent refresh or a revocation
    if rec.used || f.revoked {
        return nil, ErrInvalidGrant
    }
    rec.used = true
    dev.LastSeen, dev.Region = now, region
    return &Issued{
        AccessToken:  AccessClaims{Sub: dev.Account, DeviceID: dev.ID,
            Jkt: dev.Jkt, Exp: now.Add(e.Policy.AccessTTL)},
        RefreshToken: t.issue(f, now),
    }, nil
}

// ---- resource-server side of Fig 15.3: short JWTs + the revocation feed ----

func APIAllows(at AccessClaims, feed *Feed, useFeed bool, now time.Time) error {
    if now.After(at.Exp) {
        return errors.New("401 invalid_token (expired)")
    }
    if useFeed && feed.Revoked(at.DeviceID) {
        return errors.New("401 invalid_token (device signed out)")
    }
    return nil
}
