// rotation.go
// Listing 31.1 — Go: key rotation job for murmur-auth's access-token signing
// keys, with JWKS overlap. Every key goes through four states:
//
// next published in the JWKS, not yet signing (resource servers learn it in
// advance) current   signing new tokens (exactly one)
// previous no longer signing, still published until every token it signed has
// expired retired   removed from the JWKS; the private key is destroyed
//
// Scheduled rotation never invalidates a valid token. Emergency rotation (a
// suspected compromise) removes the key from the JWKS at once and revokes what
// it signed.
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "math/big"
    "strings"
    "sync"
    "time"
)

var b64 = base64.RawURLEncoding

type State string

const (
    Next     State = "next"
    Current  State = "current"
    Previous State = "previous"
)

type SigningKey struct {
    Kid       string
    // production: a non-exportable KMS/HSM key; only Sign() is exposed
    priv      *ecdsa.PrivateKey
    State     State
    Since     time.Time
    // when this key last signed: bounds how long it must stay published
    LastToken time.Time
}

type KeyRing struct {
    mu          sync.Mutex
    keys        []*SigningKey
    Period      time.Duration // scheduled rotation, e.g. 30 days
    TokenTTL    time.Duration // access tokens: 5 minutes (Ch 13)
    Skew        time.Duration // tolerated clock skew at resource servers
    CacheTTL    time.Duration // how long resource servers may cache the JWKS
    Log         []string
    newKey      func() *ecdsa.PrivateKey
    revokedKids map[string]bool
}

func NewKeyRing(now time.Time) *KeyRing {
    r := &KeyRing{Period: 30 * 24 * time.Hour, TokenTTL: 5 * time.Minute,
        Skew: 30 * time.Second,
        CacheTTL: 10 * time.Minute, revokedKids: map[string]bool{},
        newKey: func() *ecdsa.PrivateKey { k,
        _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }}
    r.add(Current, now)
    r.add(Next, now)
    return r
}

func (r *KeyRing) add(s State, now time.Time) *SigningKey {
    id := make([]byte, 6)
    rand.Read(id)
    k := &SigningKey{Kid: "at-" + b64.EncodeToString(id), priv: r.newKey(),
        State: s, Since: now}
    r.keys = append(r.keys, k)
    return k
}

func (r *KeyRing) find(s State) *SigningKey {
    for _, k := range r.keys {
        if k.State == s {
            return k
        }
    }
    return nil
}

// Tick is the job: run it every few minutes. Every transition waits long enough
// that no resource server can be surprised: a key is published (as "next") for
// at least one JWKS cache lifetime before it signs, and stays published after
// its last token until that token has expired at every resource server.
func (r *KeyRing) Tick(now time.Time) {
    r.mu.Lock()
    defer r.mu.Unlock()
    cur, next := r.find(Current), r.find(Next)
    if cur != nil && next != nil && now.Sub(cur.Since) >= r.Period && now.Sub(
        next.Since) >= r.CacheTTL {
        cur.State, cur.Since = Previous, now
        next.State, next.Since = Current, now
        r.add(Next, now)
        r.Log = append(r.Log,
            fmt.Sprintf(
            "%s rotate: %s → previous, %s → current, new next published",
            day(now), cur.Kid, next.Kid))
    }
    keep := r.keys[:0]
    for _, k := range r.keys {
        if k.State == Previous && now.After(k.LastToken.Add(
            r.TokenTTL+r.Skew+r.CacheTTL)) {
            k.priv = nil // destroy
            r.Log = append(r.Log,
                fmt.Sprintf(
                "%s retire: %s removed from JWKS, private key destroyed",
                day(now), k.Kid))
            continue
        }
        keep = append(keep, k)
    }
    r.keys = keep
}

// Emergency: the current key may be compromised. Promote "next" (already
// published, so resource servers accept it at once), remove the suspect key
// IMMEDIATELY, and report its kid so that resource servers drop cached JWKS and
// reject its tokens, even unexpired ones.
func (r *KeyRing) Emergency(now time.Time) string {
    r.mu.Lock()
    defer r.mu.Unlock()
    cur, next := r.find(Current), r.find(Next)
    keep := r.keys[:0]
    for _, k := range r.keys {
        if k != cur {
            keep = append(keep, k)
        }
    }
    r.keys = keep
    next.State, next.Since = Current, now
    r.add(Next, now)
    r.revokedKids[cur.Kid] = true
    r.Log = append(r.Log,
        fmt.Sprintf("%s EMERGENCY: %s removed and revoked; %s signing",
        day(now), cur.Kid, next.Kid))
    return cur.Kid
}

func (r *KeyRing) Sign(claims map[string]any, now time.Time) string {
    r.mu.Lock()
    k := r.find(Current)
    k.LastToken = now
    r.mu.Unlock()
    h, _ := json.Marshal(map[string]string{"typ": "at+jwt", "alg": "ES256",
        "kid": k.Kid})
    c, _ := json.Marshal(claims)
    in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
    d := sha256.Sum256([]byte(in))
    rr, s, _ := ecdsa.Sign(rand.Reader, k.priv, d[:])
    sig := make([]byte, 64)
    rr.FillBytes(sig[:32])
    s.FillBytes(sig[32:])
    return in + "." + b64.EncodeToString(sig)
}

type JWK struct{ Kid, X, Y string }

// JWKS is what /.well-known/jwks.json serves: next, current and previous keys.
func (r *KeyRing) JWKS() []JWK {
    r.mu.Lock()
    defer r.mu.Unlock()
    var out []JWK
    for _, k := range r.keys {
        out = append(out, JWK{k.Kid,
            b64.EncodeToString(k.priv.X.FillBytes(make([]byte, 32))),
            b64.EncodeToString(k.priv.Y.FillBytes(make([]byte, 32)))})
    }
    return out
}

// ── resource server side: cached JWKS, refreshed on expiry or on an unknown
// kid (rate-limited) ──
type Verifier struct {
    Fetch       func() []JWK
    // revocation feed for emergency-revoked kids
    Revoked     func() map[string]bool
    CacheTTL    time.Duration
    cache       map[string]*ecdsa.PublicKey
    fetched     time.Time
    lastRefetch time.Time
}

func (v *Verifier) Verify(tok string, now time.Time) error {
    p := strings.Split(tok, ".")
    hb, _ := b64.DecodeString(p[0])
    var h struct{ Kid string }
    json.Unmarshal(hb, &h)
    if v.Revoked()[h.Kid] {
        return errors.New("kid revoked")
    }
    if v.cache == nil || now.Sub(v.fetched) > v.CacheTTL {
        v.load(now)
    }
    key, ok := v.cache[h.Kid]
    // unknown kid: refetch at most once a minute
    if !ok && now.Sub(v.lastRefetch) > time.Minute {
        v.load(now)
        v.lastRefetch = now
        key, ok = v.cache[h.Kid]
    }
    if !ok {
        return errors.New("unknown kid")
    }
    cb, _ := b64.DecodeString(p[1])
    var c struct{ Exp int64 }
    json.Unmarshal(cb, &c)
    sig, _ := b64.DecodeString(p[2])
    d := sha256.Sum256([]byte(p[0] + "." + p[1]))
    if !ecdsa.Verify(key, d[:], new(big.Int).SetBytes(sig[:32]),
        new(big.Int).SetBytes(sig[32:])) {
        return errors.New("bad signature")
    }
    if now.Unix() > c.Exp {
        return errors.New("expired")
    }
    return nil
}

func (v *Verifier) load(now time.Time) {
    v.cache = map[string]*ecdsa.PublicKey{}
    for _, k := range v.Fetch() {
        x, _ := b64.DecodeString(k.X)
        y, _ := b64.DecodeString(k.Y)
        v.cache[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(),
            X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
    }
    v.fetched = now
}

func day(t time.Time) string { return t.Format("Jan 02 15:04") }
