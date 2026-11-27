// main.go
// main.go — drives Listing 31.1 through 75 simulated days: scheduled rotations,
// a token issued a minute before a rotation, and an emergency rotation after a
// suspected key compromise.
package main

import (
    "fmt"
    "time"
)

func main() {
    t0 := time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)
    ring := NewKeyRing(t0)
    rs := &Verifier{Fetch: ring.JWKS,
        Revoked: func() map[string]bool { return ring.revokedKids },
        CacheTTL: ring.CacheTTL}
    tok := func(now time.Time) string {
        return ring.Sign(map[string]any{"sub": "alice",
            "exp": now.Add(ring.TokenTTL).Unix()}, now)
    }
    check := func(label, t string, now time.Time) {
        err := rs.Verify(t, now)
        res := "accepted"
        if err != nil {
            res = "rejected: " + err.Error()
        }
        fmt.Printf("  %-58s %s\n", label, res)
    }
    now := t0
    var beforeRotation string
    for now.Before(t0.Add(75 * 24 * time.Hour)) {
        ring.Tick(now)
        if now.Equal(t0.Add(30*24*time.Hour - time.Minute)) {
            beforeRotation = tok(now)
            check("token signed 1 min before the day-30 rotation, at once",
                beforeRotation, now)
        }
        if now.Equal(t0.Add(30*24*time.Hour + 3*time.Minute)) {
            check("the same token 3 min later (after the rotation)",
                beforeRotation, now)
            check("a new token from the new current key", tok(now), now)
        }
        if now.Equal(t0.Add(30*24*time.Hour + 10*time.Minute)) {
            check("the old token 10 min later (expired anyway)", beforeRotation,
                now)
        }
        now = now.Add(time.Minute)
        if now.Equal(t0.Add(45 * 24 * time.Hour)) {
            // an attacker copied the key; tokens it signs are valid-looking
            stolen := tok(now)
            check("day 45: token from the (soon suspected) current key", stolen,
                now)
            ring.Emergency(now)
            check("same token right after EMERGENCY rotation", stolen,
                now.Add(time.Second))
            check("a token from the promoted key, right away",
                tok(now.Add(time.Second)), now.Add(time.Second))
        }
    }
    fmt.Println("  timeline:")
    for _, l := range ring.Log {
        fmt.Println("   ", l)
    }
    fmt.Printf("  JWKS now: %d keys (current + next%s)\n", len(ring.JWKS()),
        map[bool]string{true: " + previous", false: ""}[len(ring.JWKS()) == 3])
}
