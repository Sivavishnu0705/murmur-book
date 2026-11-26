// directory.go
// Listing 18.3 — Go: Murmur's prekey directory. Publish a bundle (signature checked), fetch a
// bundle and consume one one-time prekey ATOMICALLY, rate-limit fetchers, warn devices when
// their one-time prekeys run low. The server distributes keys; clients verify them.
package main

import (
       "crypto/ed25519"
       "errors"
       "math/big"
       "sync"
       "time"
)

type SignedPrekey struct {
       ID  uint32
       Pub [32]byte
       Sig [64]byte // XEdDSA: Sig(IK, Encode(SPK)), Encode = 0x05 ‖ pub
}

type OneTimePrekey struct {
       ID  uint32
       Pub [32]byte
}

type Bundle struct { // what a fetcher receives
       Identity [32]byte
       SPK      SignedPrekey
       OPK      *OneTimePrekey // nil when exhausted: X3DH runs with three DHs (§18.5)
       // PQXDH (§18.7): PQ prekey (signed), one-time if available, else last-resort.
}

type deviceKeys struct {
       identity [32]byte
       spk      SignedPrekey
       opks     []OneTimePrekey // FIFO
       lowSent  time.Time
}

type Directory struct {
       mu       sync.Mutex
       devices  map[string]*deviceKeys
       limiter  *Limiter
       LowWater int              // e.g. 20: ask the device to upload more
       Notify   func(dev string) // push "replenish prekeys" (content-free) to the device
}

func NewDirectory(perMinute int) *Directory {
       return &Directory{devices: map[string]*deviceKeys{}, limiter: NewLimiter(perMinute), LowWater: 20,
              Notify: func(string) {}}
}

var (
       ErrBadSignature = errors.New("signed prekey signature invalid")
       ErrRateLimited  = errors.New("429 too many bundle requests")
       ErrUnknown      = errors.New("404 unknown device")
)

// Publish is called by the device itself over its authenticated session (Ch 15). Checking the
// SPK signature here rejects garbage early; it does NOT replace the client's own check.
func (d *Directory) Publish(dev string, identity [32]byte, spk SignedPrekey, opks []OneTimePrekey) error {
       if !VerifyXEdDSA(identity, append([]byte{0x05}, spk.Pub[:]...), spk.Sig) {
              return ErrBadSignature
       }
       d.mu.Lock()
       defer d.mu.Unlock()
       k, ok := d.devices[dev]
       if !ok || k.identity != identity { // new device, or identity changed (re-registration: Ch 20)
              k = &deviceKeys{identity: identity}
              d.devices[dev] = k
       }
       k.spk = spk // rotation: the newest SPK replaces the old one; the DEVICE keeps old private keys
       k.opks = append(k.opks, opks...)
       return nil
}

// Fetch returns dev's bundle to requester, consuming at most one OPK. The pop happens under
// the same lock as the read, so two concurrent fetchers can never receive the same OPK.
// (In a database: DELETE … WHERE id = (SELECT … LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING ….)
func (d *Directory) Fetch(requester, dev string, now time.Time) (*Bundle, error) {
       if !d.limiter.Allow(requester+"→"+dev, now) || !d.limiter.Allow(requester, now) {
              return nil, ErrRateLimited
       }
       d.mu.Lock()
       k, ok := d.devices[dev]
       if !ok {
              d.mu.Unlock()
              return nil, ErrUnknown
       }
       b := &Bundle{Identity: k.identity, SPK: k.spk}
       if len(k.opks) > 0 {
              opk := k.opks[0]
              k.opks = k.opks[1:]
              b.OPK = &opk
       }
       low := len(k.opks) < d.LowWater && now.Sub(k.lowSent) > time.Hour
       if low {
              k.lowSent = now
       }
       d.mu.Unlock()
       if low {
              d.Notify(dev)
       }
       return b, nil
}

func (d *Directory) Remaining(dev string) int {
       d.mu.Lock()
       defer d.mu.Unlock()
       return len(d.devices[dev].opks)
}

// ---- rate limiting: token bucket per key ----
type Limiter struct {
       mu      sync.Mutex
       rate    float64 // tokens per second
       burst   float64
       buckets map[string]*bucket
}
type bucket struct {
       tokens float64
       last   time.Time
}

func NewLimiter(perMinute int) *Limiter {
       return &Limiter{rate: float64(perMinute) / 60, burst: float64(perMinute), buckets: map[string]*bucket{}}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
       l.mu.Lock()
       defer l.mu.Unlock()
       b, ok := l.buckets[key]
       if !ok {
              b = &bucket{tokens: l.burst, last: now}
              l.buckets[key] = b
       }
       b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
       b.last = now
       if b.tokens < 1 {
              return false
       }
       b.tokens--
       return true
}

// ---- XEdDSA verification: convert the X25519 u-coordinate to an Ed25519 key (sign bit 0) ----
var p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

func VerifyXEdDSA(xPub [32]byte, msg []byte, sig [64]byte) bool {
       le := func(b []byte) []byte {
              r := make([]byte, len(b))
              for i := range b {
                     r[i] = b[len(b)-1-i]
              }
              return r
       }
       u := new(big.Int).SetBytes(le(xPub[:]))
       u.Mod(u, p25519)
       num := new(big.Int).Sub(u, big.NewInt(1))
       den := new(big.Int).Add(u, big.NewInt(1))
       den.ModInverse(den, p25519)
       if den == nil {
              return false
       }
       y := num.Mul(num, den)
       y.Mod(y, p25519)
       yb := make([]byte, 32)
       y.FillBytes(yb)
       edPub := le(yb) // little-endian y, sign bit 0
       return ed25519.Verify(ed25519.PublicKey(edPub), msg, sig[:])
}
