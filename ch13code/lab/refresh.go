// refresh.go
// Listing 13.4 — Go: refresh token rotation with family revocation, DPoP binding for a public
// client, idle and absolute lifetimes. Refresh tokens are stored only as SHA-256 hashes.
package main

import (
       "crypto/rand"
       "crypto/sha256"
       "errors"
       "sync"
       "time"
)

type Family struct {
       ID        string
       Sub       string
       Jkt       string    // DPoP key the family is bound to, fixed at the first token request
       Created   time.Time // absolute lifetime counts from here
       Revoked   bool
       RevokedBy string
}

type rtRecord struct {
       fam      *Family
       used     bool
       issuedAt time.Time
}

type RefreshService struct {
       mu        sync.Mutex
       byHash    map[[32]byte]*rtRecord
       Idle      time.Duration // e.g. 30 days without use → expired
       Absolute  time.Duration // e.g. 90 days since login → expired, whatever the activity
       AccessTTL time.Duration
       Events    func(string) // security events → anomaly detection (Ch 15 §15.8)
}

func NewRefreshService() *RefreshService {
       return &RefreshService{byHash: map[[32]byte]*rtRecord{}, Idle: 30 * 24 * time.Hour,
              Absolute: 90 * 24 * time.Hour, AccessTTL: 5 * time.Minute, Events: func(string) {}}
}

func randTok() string { b := make([]byte, 32); rand.Read(b); return b64.EncodeToString(b) }

type Issued struct {
       Access AccessToken
       AT, RT string
}

// StartFamily runs after a successful authorization_code grant whose DPoP proof had key jkt.
func (s *RefreshService) StartFamily(sub, jkt string, now time.Time) Issued {
       s.mu.Lock()
       defer s.mu.Unlock()
       return s.issue(&Family{ID: randTok()[:8], Sub: sub, Jkt: jkt, Created: now}, now)
}

func (s *RefreshService) issue(f *Family, now time.Time) Issued {
       rt := randTok()
       s.byHash[sha256.Sum256([]byte(rt))] = &rtRecord{fam: f, issuedAt: now}
       return Issued{AT: randTok(), RT: rt,
              Access: AccessToken{Sub: f.Sub, Jkt: f.Jkt, Exp: now.Add(s.AccessTTL)}}
}

var ErrInvalidGrant = errors.New("invalid_grant")

// Refresh handles grant_type=refresh_token. proofJkt is the thumbprint from the request's
// verified DPoP proof (Listing 13.3, called with accessToken="").
func (s *RefreshService) Refresh(rt, proofJkt string, now time.Time) (Issued, error) {
       s.mu.Lock()
       defer s.mu.Unlock()
       rec, ok := s.byHash[sha256.Sum256([]byte(rt))]
       if !ok {
              return Issued{}, ErrInvalidGrant
       }
       f := rec.fam
       switch {
       case f.Revoked:
              return Issued{}, ErrInvalidGrant
       case proofJkt != f.Jkt:
              // A copied refresh token without the device's private key: refuse, but do NOT revoke —
              // otherwise anyone holding a leaked token could log the victim out at will.
              s.Events("refresh with wrong DPoP key, family " + f.ID)
              return Issued{}, ErrInvalidGrant
       case rec.used:
              // Reuse of a rotated token: two parties hold this family. Revoke all of it.
              f.Revoked, f.RevokedBy = true, "reuse"
              s.Events("refresh token reuse, family " + f.ID + " revoked")
              return Issued{}, ErrInvalidGrant
       case now.Sub(f.Created) > s.Absolute:
              f.Revoked, f.RevokedBy = true, "absolute lifetime"
              return Issued{}, ErrInvalidGrant
       case now.Sub(rec.issuedAt) > s.Idle:
              f.Revoked, f.RevokedBy = true, "idle"
              return Issued{}, ErrInvalidGrant
       }
       rec.used = true
       return s.issue(f, now), nil
}

// Lookup lets the resource server find access tokens (stand-in for JWT validation).
type tokenDB struct {
       mu sync.Mutex
       m  map[string]*AccessToken
}

func (d *tokenDB) put(t string, a AccessToken) { d.mu.Lock(); d.m[t] = &a; d.mu.Unlock() }
func (d *tokenDB) get(t string) (*AccessToken, bool) {
       d.mu.Lock()
       defer d.mu.Unlock()
       a, ok := d.m[t]
       return a, ok
}
