// registry.go
// Listing 15.2 — Go: Murmur's device registry, session list API and
// revoke-device endpoint. One device = one session = one refresh-token family =
// one DPoP key. Adding a device requires step-up (acr=phr, auth_time ≤ 5 min);
// every change notifies the account's other devices and is published to
// resource servers through the revocation feed (Fig 15.3).
package main

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "sort"
    "strings"
    "sync"
    "time"
)

type Device struct {
    ID         string    `json:"id"`
    Account    string    `json:"-"`
    Name       string    `json:"name"`     // user-chosen, e.g. "Alice's iPad"
    Platform   string    `json:"platform"` // "android" | "ios"
    // DPoP key thumbprint (Ch 13): THE device key for sessions
    Jkt        string    `json:"-"`
    Created    time.Time `json:"created"`
    LastSeen   time.Time `json:"last_seen"`
    // coarse (country), never precise location (§15.8)
    Region     string    `json:"last_region"`
    AttestedAt time.Time `json:"-"`
    Status     string    `json:"status"` // "active" | "revoked"
    RevokedBy  string    `json:"-"`
    RevokedWhy string    `json:"-"`
    Current    bool      `json:"current,omitempty"` // filled per request
}

// Feed carries revocations to resource servers and clients. In production: a
// pub/sub topic that murmur-api instances subscribe to, plus push messages to
// the affected device.
type Feed struct {
    mu      sync.Mutex
    // device ID → revoked at; kept for ≥ access-token lifetime
    revoked map[string]time.Time
    events  []string
}

func NewFeed() *Feed { return &Feed{revoked: map[string]time.Time{}} }
func (f *Feed) Revoked(dev string) bool {
    f.mu.Lock()
    defer f.mu.Unlock()
    _, ok := f.revoked[dev]
    return ok
}
func (f *Feed) publish(dev string, at time.Time, ev string) {
    f.mu.Lock()
    f.revoked[dev] = at
    f.events = append(f.events, ev)
    f.mu.Unlock()
}
func (f *Feed) Notify(ev string) { f.mu.Lock(); f.events = append(f.events, ev);
    f.mu.Unlock() }
func (f *Feed) Drain() []string {
    f.mu.Lock()
    defer f.mu.Unlock()
    e := f.events
    f.events = nil
    return e
}

type Registry struct {
    mu      sync.Mutex
    devices map[string]*Device
    feed    *Feed
    tokens  *Tokens // refresh families, Listing 15.3
}

// Auth is what murmur-api knows about the caller after validating its access
// token and DPoP proof (Listings 10.2, 13.3): account, device, and the
// authentication context of the token.
type Auth struct {
    Account, Device, Acr string
    AuthTime             time.Time
    Scopes               []string
}

var ErrStepUp = errors.New(
    `insufficient_user_authentication: acr_values="phr", max_age="300"`)

func randID() string { b := make([]byte, 8); rand.Read(b);
    return hex.EncodeToString(b) }

func has(xs []string, s string) bool {
    for _, x := range xs {
        if x == s {
            return true
        }
    }
    return false
}

// Enroll adds a device. The FIRST device of a new account is enrolled by the
// sign-up flow itself; every later one needs step-up on an authenticated
// session (Ch 12 §12.8, Ch 14 §14.6) and passes Chapter 9's attestation check
// (attestOK). a == nil only for the sign-up flow, which creates account
// signupAccount with this device.
func (r *Registry) Enroll(a *Auth, signupAccount, name, platform, jkt string,
    attestOK bool, now time.Time) (*Device, error) {
    if a != nil && (!has(a.Scopes,
        "devices:enroll") || a.Acr != "phr" || now.Sub(
        a.AuthTime) > 5*time.Minute) {
        return nil, ErrStepUp
    }
    if !attestOK {
        return nil, errors.New("attestation failed: device not enrolled")
    }
    acct := signupAccount
    if a != nil {
        acct = a.Account
    }
    r.mu.Lock()
    d := &Device{ID: "dev-" + randID()[:6], Account: acct, Name: name,
        Platform: platform, Jkt: jkt,
        Created: now, LastSeen: now, AttestedAt: now, Status: "active"}
    r.devices[d.ID] = d
    r.mu.Unlock()
    // adding a device is a security-critical event: tell every other device
    if a != nil {
        r.feed.Notify(fmt.Sprintf(
            "notify %s's other devices: new device %q added", acct, name))
    }
    return d, nil
}

func (r *Registry) Get(id string) (*Device, bool) {
    r.mu.Lock()
    defer r.mu.Unlock()
    d, ok := r.devices[id]
    return d, ok
}

// List is GET /v1/devices: the user-visible "Your devices" screen.
func (r *Registry) List(a *Auth) []Device {
    r.mu.Lock()
    defer r.mu.Unlock()
    var out []Device
    for _, d := range r.devices {
        if d.Account == a.Account && d.Status == "active" {
            c := *d
            c.Current = d.ID == a.Device
            out = append(out, c)
        }
    }
    sort.Slice(out, func(i,
        j int) bool { return out[i].Created.Before(out[j].Created) })
    return out
}

// Revoke is DELETE /v1/devices/{id}: remote sign-out. Signing out ANOTHER
// device is a sensitive action and needs a recent strong authentication (5 min,
// any phishing-resistant acr); signing out the current device never does.
func (r *Registry) Revoke(a *Auth, id, why string, now time.Time) error {
    r.mu.Lock()
    d, ok := r.devices[id]
    r.mu.Unlock()
    if !ok || d.Account != a.Account || d.Status != "active" {
        // same answer for "not yours": no device-ID probing
        return errors.New("not_found")
    }
    if id != a.Device && (a.Acr != "phr" || now.Sub(
        a.AuthTime) > 5*time.Minute) {
        return ErrStepUp
    }
    r.revoke(d, a.Device, why, now)
    return nil
}

func (r *Registry) revoke(d *Device, by, why string, now time.Time) {
    r.mu.Lock()
    d.Status, d.RevokedBy, d.RevokedWhy = "revoked", by, why
    r.mu.Unlock()
    // 1 refresh family
    r.tokens.RevokeDevice(d.ID)
    // 2 APIs
    r.feed.publish(d.ID, now,
        fmt.Sprintf("revocation feed: device %s (%s) → resource servers", d.ID,
        why))
    // 3 the device
    r.feed.Notify(fmt.Sprintf(
        "push to %s: session_revoked (hint; app re-checks /v1/session)", d.ID))
    // 4 the user
    r.feed.Notify(fmt.Sprintf("notify %s's other devices: %q signed out (%s)",
        d.Account, d.Name, why))
    // 5 Part IV: the device leaves the account's E2EE device list (Ch 20).
}

// RevokeAll signs out every device except (optionally) the current one: "sign
// out everywhere", passkey removal, account recovery, compromise response.
func (r *Registry) RevokeAll(account, keep, why string, now time.Time) int {
    r.mu.Lock()
    var victims []*Device
    for _, d := range r.devices {
        if d.Account == account && d.Status == "active" && d.ID != keep {
            victims = append(victims, d)
        }
    }
    r.mu.Unlock()
    for _, d := range victims {
        r.revoke(d, keep, why, now)
    }
    return len(victims)
}

// HTTP wiring for the session list API (auth extraction elided: it is Listings
// 10.2 + 13.3).
func (r *Registry) Handler(authOf func(*http.Request) *Auth,
    clock func() time.Time) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("GET /v1/devices", func(w http.ResponseWriter,
        q *http.Request) {
        json.NewEncoder(w).Encode(r.List(authOf(q)))
    })
    mux.HandleFunc("DELETE /v1/devices/{id}", func(w http.ResponseWriter,
        q *http.Request) {
        err := r.Revoke(authOf(q), q.PathValue("id"), "remote sign-out",
        clock())
        switch {
        case err == nil:
            w.WriteHeader(http.StatusNoContent)
        case errors.Is(err, ErrStepUp):
            w.Header().Set("WWW-Authenticate",
            `DPoP error="insufficient_user_authentication", ` +
            `acr_values="phr", max_age="300"`)
            http.Error(w, err.Error(), http.StatusUnauthorized)
        default:
            http.Error(w, strings.TrimSpace(err.Error()), http.StatusNotFound)
        }
    })
    return mux
}
