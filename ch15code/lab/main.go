// main.go
// Listing 15.4 — Go: lab driver for the Murmur session service: device-scoped
// sessions, "Your devices", step-up for adding a device, remote sign-out and
// revocation propagation.
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "time"
)

func main() {
    now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
    feed := NewFeed()
    tokens := NewTokens()
    reg := &Registry{devices: map[string]*Device{}, feed: feed, tokens: tokens}
    attestOK := map[string]bool{}
    ep := &RefreshEndpoint{Tokens: tokens, Registry: reg, Feed: feed,
        Attest: func(d string) bool { return attestOK[d] },
        Policy: RefreshPolicy{Idle: 30 * 24 * time.Hour,
        Absolute: 90 * 24 * time.Hour,
            AttestEvery: 7 * 24 * time.Hour, AccessTTL: 5 * time.Minute}}
    events := func() {
        for _, e := range feed.Drain() {
            fmt.Printf("      → %s\n", e)
        }
    }
    step := func(s string, a ...any) { fmt.Printf("  "+s+"\n", a...) }

    fmt.Println("── Sign-up and first device ──")
    phone, _ := reg.Enroll(nil, "alice", "Alice's Pixel", "android",
        "jkt-phone", true, now)
    attestOK[phone.ID] = true
    phoneRT := tokens.Start(phone.ID, now)
    step("enrolled %s (%s)", phone.Name, phone.ID)
    events()

    fmt.Println("── Adding a second device (step-up gate) ──")
    stale := &Auth{Account: "alice", Device: phone.ID, Acr: "phr",
        AuthTime: now.Add(-3 * time.Hour), Scopes: []string{"devices:enroll"}}
    _, err := reg.Enroll(stale, "", "Alice's iPad", "ios", "jkt-ipad", true,
        now)
    step("iPad, phone session signed in 3 h ago:      %v", err)
    fresh := &Auth{Account: "alice", Device: phone.ID, Acr: "phr",
        AuthTime: now.Add(-1 * time.Minute), Scopes: []string{"devices:enroll"}}
    _, err = reg.Enroll(fresh, "", "Alice's iPad", "ios", "jkt-ipad", false,
        now)
    step("iPad, fresh passkey step-up, attestation ✗:  %v", err)
    ipad, err := reg.Enroll(fresh, "", "Alice's iPad", "ios", "jkt-ipad", true,
        now)
    step("iPad, fresh passkey step-up, attestation ✓:  enrolled %s err=%v",
        ipad.ID, err)
    attestOK[ipad.ID] = true
    ipadRT := tokens.Start(ipad.ID, now)
    events()

    // HTTP: GET /v1/devices and DELETE /v1/devices/{id}
    var who *Auth
    srv := httptest.NewServer(reg.Handler(func(*http.Request) *Auth {
        return who }, func() time.Time { return now }))
    defer srv.Close()
    call := func(method, path string) string {
        req, _ := http.NewRequest(method, srv.URL+path, nil)
        resp, _ := http.DefaultClient.Do(req)
        b, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        return fmt.Sprintf("%d %s", resp.StatusCode, b)
    }
    fmt.Println("── \"Your devices\" (GET /v1/devices from the phone) ──")
    who = &Auth{Account: "alice", Device: phone.ID, Acr: "phr",
        AuthTime: now.Add(-2 * time.Hour)}
    var list []map[string]any
    req, _ := http.NewRequest("GET", srv.URL+"/v1/devices", nil)
    resp, _ := http.DefaultClient.Do(req)
    json.NewDecoder(resp.Body).Decode(&list)
    resp.Body.Close()
    for _, d := range list {
        cur := ""
        if d["current"] == true {
            cur = "  ← this device"
        }
        step("%-14s %-8s %-7s added %s%s", d["name"], d["platform"],
            d["status"], d["created"].(string)[:10], cur)
    }

    fmt.Println("── Refresh, then remote sign-out of the iPad ──")
    iss, err := ep.Refresh(ipadRT, "jkt-ipad", "DE", now)
    step(
        "iPad refresh:                               access token for %s, " +
        "err=%v", iss.AccessToken.DeviceID, err)
    ipadAT, ipadRT := iss.AccessToken, iss.RefreshToken
    step("DELETE iPad, phone auth 2 h old:            %s", trim(call("DELETE",
        "/v1/devices/"+ipad.ID)))
    who.AuthTime = now.Add(-30 * time.Second)
    step("DELETE iPad after passkey step-up:          %s", trim(call("DELETE",
        "/v1/devices/"+ipad.ID)))
    events()
    now = now.Add(1 * time.Minute)
    step("iPad API call, JWT only (no feed):          %v",
        orOK(APIAllows(ipadAT, feed, false, now)))
    step("iPad API call, JWT + revocation feed:       %v",
        orOK(APIAllows(ipadAT, feed, true, now)))
    _, err = ep.Refresh(ipadRT, "jkt-ipad", "DE", now)
    step("iPad refresh:                               %v", err)
    step("probe DELETE of a device ID from elsewhere: %s", trim(call("DELETE",
        "/v1/devices/dev-000000")))

    fmt.Println("── Attestation re-check at refresh (8 days later) ──")
    now = now.Add(8 * 24 * time.Hour)
    attestOK[phone.ID] = false // e.g. bootloader unlocked, or app repackaged
    _, err = ep.Refresh(phoneRT, "jkt-phone", "DE", now)
    step("phone refresh, attestation fails:           %v", err)
    attestOK[phone.ID] = true
    iss, err = ep.Refresh(phoneRT, "jkt-phone", "DE", now)
    step("phone refresh after fixing the device:      ok=%v err=%v", iss != nil,
        err)
    events()

    fmt.Println("── Stolen refresh token ──")
    _, err = ep.Refresh(iss.RefreshToken, "jkt-attacker", "BR", now)
    step("thief, current RT, own DPoP key:            %v", err)
    // malware replays the OLD token with the device key
    _, err = ep.Refresh(phoneRT, "jkt-phone", "DE", now)
    step("old RT replayed with the device key:        %v", err)
    events()
    _, err = ep.Refresh(iss.RefreshToken, "jkt-phone", "DE", now)
    step(
        "Alice's current RT afterwards:              %v  (sign in again; " +
        "event shown to user)", err)
}

func trim(s string) string {
    s = strings.TrimSpace(s)
    if len(s) > 90 {
        return s[:90] + "…"
    }
    return s
}

func orOK(err error) any {
    if err == nil {
        return "200 OK  (until the token expires, up to 5 min)"
    }
    return err
}
