// limits.go — the token-bucket Limiter and the XEdDSA verifier of Listing 18.3,
// reused unchanged by the Chapter 27 server (listed under "Described only").
package main

import (
    "crypto/ed25519"
    "math/big"
    "sync"
    "time"
)

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
    return &Limiter{rate: float64(perMinute) / 60, burst: float64(perMinute),
        buckets: map[string]*bucket{}}
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

// ---- XEdDSA verification: convert the X25519 u-coordinate to an Ed25519 key
// (sign bit 0) ----
var p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255),
    big.NewInt(19))

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
