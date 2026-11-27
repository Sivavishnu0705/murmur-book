// push.go
// Listing 27.10 — Go: push gateway (murmur-push) clients for APNs and FCM.
// Payloads carry no content and no sender (Ch 21 §21.4): on iOS an alert with a
// generic placeholder and mutable-content, so the Notification Service
// Extension fetches and decrypts; on Android a high-priority data message. Both
// use a collapse key, so a burst of messages is one wakeup.
package main

import (
    "bytes"
    "crypto"
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"
)

var (
    apnsPayload = []byte(
    `{"aps":{"alert":{"title":"Murmur","body":"New ` +
    `message"},"mutable-content":1},"v":1}`)
    collapseID  = "murmur-new"
)

// Outcome tells the gateway what to do with the device's push token.
type Outcome int

const (
    Delivered Outcome = iota
    // the token is dead: delete it (device uninstalled or re-registered)
    DropToken
    // provider throttling or outage: back off, the relay queue still holds the
    // message
    Retry
)

func es256JWT(key *ecdsa.PrivateKey, header, claims map[string]any) string {
    h, _ := json.Marshal(header)
    c, _ := json.Marshal(claims)
    in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
    d := sha256.Sum256([]byte(in))
    r, s, _ := ecdsa.Sign(rand.Reader, key, d[:])
    sig := make([]byte, 64)
    r.FillBytes(sig[:32])
    s.FillBytes(sig[32:])
    return in + "." + b64.EncodeToString(sig)
}

// ── APNs: token-based (.p8) authentication over HTTP/2 ──
type APNs struct {
    // Base: https://api.push.apple.com (prod) or api.sandbox…
    Base, Topic, TeamID, KeyID string
    Key                        *ecdsa.PrivateKey
    HTTP                       *http.Client
    Clock                      func() time.Time
    mu                         sync.Mutex
    jwt                        string
    jwtAt                      time.Time
}

// providerToken: Apple rejects tokens older than one hour and throttles
// regeneration more often than every 20 minutes, so reuse for 50 minutes.
func (a *APNs) providerToken(force bool) string {
    a.mu.Lock()
    defer a.mu.Unlock()
    now := a.Clock()
    if force || a.jwt == "" || now.Sub(a.jwtAt) > 50*time.Minute {
        a.jwt = es256JWT(a.Key, map[string]any{"alg": "ES256", "kid": a.KeyID},
            map[string]any{"iss": a.TeamID, "iat": now.Unix()})
        a.jwtAt = now
    }
    return a.jwt
}

func (a *APNs) Send(deviceToken string) Outcome {
    for attempt := 0; attempt < 2; attempt++ {
        req, _ := http.NewRequest("POST",
            a.Base+"/3/device/"+url.PathEscape(deviceToken),
            bytes.NewReader(apnsPayload))
        req.Header.Set("authorization", "bearer "+a.providerToken(attempt > 0))
        req.Header.Set("apns-topic", a.Topic)
        req.Header.Set("apns-push-type", "alert")
        req.Header.Set("apns-priority", "10")
        req.Header.Set("apns-collapse-id", collapseID)
        req.Header.Set("apns-expiration",
            fmt.Sprint(a.Clock().Add(24*time.Hour).Unix()))
        resp, err := a.HTTP.Do(req)
        if err != nil {
            return Retry
        }
        var body struct{ Reason string }
        json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
        resp.Body.Close()
        switch {
        case resp.StatusCode == 200:
            return Delivered
        case resp.StatusCode == 410, body.Reason == "BadDeviceToken",
            body.Reason == "DeviceTokenNotForTopic":
            return DropToken
        case resp.StatusCode == 403 && body.Reason == "ExpiredProviderToken":
            continue // regenerate once
        default:
            return Retry // 429 TooManyRequests, 5xx
        }
    }
    return Retry
}

// ── FCM: HTTP v1 API with an OAuth 2.0 token from a service-account JWT (RFC
// 7523) ──
type FCM struct {
    // Base: https://fcm.googleapis.com
    Base, TokenURI, Project, ClientEmail string
    Key                                  *rsa.PrivateKey
    HTTP                                 *http.Client
    Clock                                func() time.Time
    mu                                   sync.Mutex
    access                               string
    exp                                  time.Time
}

func (f *FCM) accessToken() (string, error) {
    f.mu.Lock()
    defer f.mu.Unlock()
    now := f.Clock()
    if f.access != "" && now.Before(f.exp.Add(-5*time.Minute)) {
        return f.access, nil
    }
    h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
    c, _ := json.Marshal(map[string]any{"iss": f.ClientEmail, "aud": f.TokenURI,
        "iat": now.Unix(),
        "exp": now.Add(time.Hour).Unix(),
        "scope": "https://www.googleapis.com/auth/firebase.messaging"})
    in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
    d := sha256.Sum256([]byte(in))
    sig, _ := rsa.SignPKCS1v15(rand.Reader, f.Key, crypto.SHA256, d[:])
    form := url.Values{"grant_type": {
        "urn:ietf:params:oauth:grant-type:jwt-bearer"},
        "assertion": {in + "." + b64.EncodeToString(sig)}}
    resp, err := f.HTTP.PostForm(f.TokenURI, form)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    var t struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }
    if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(
        &t) != nil || t.AccessToken == "" {
        return "", fmt.Errorf("token endpoint: %d", resp.StatusCode)
    }
    f.access, f.exp = t.AccessToken,
        now.Add(time.Duration(t.ExpiresIn)*time.Second)
    return f.access, nil
}

func (f *FCM) Send(registrationToken string) Outcome {
    at, err := f.accessToken()
    if err != nil {
        return Retry
    }
    msg, _ := json.Marshal(map[string]any{"message": map[string]any{
        "token":   registrationToken,
        // data-only: the app's service fetches and decrypts
        "data":    map[string]string{"v": "1"},
        "android": map[string]any{"priority": "HIGH",
        "collapse_key": collapseID, "ttl": "86400s"}}})
    req, _ := http.NewRequest("POST",
        f.Base+"/v1/projects/"+f.Project+"/messages:send", bytes.NewReader(msg))
    req.Header.Set("Authorization", "Bearer "+at)
    req.Header.Set("Content-Type", "application/json")
    resp, err := f.HTTP.Do(req)
    if err != nil {
        return Retry
    }
    defer resp.Body.Close()
    b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
    switch {
    case resp.StatusCode == 200:
        return Delivered
    case resp.StatusCode == 404 && strings.Contains(string(b), "UNREGISTERED"):
        return DropToken
    case resp.StatusCode == 400 && strings.Contains(string(b),
        "registration token"):
        return DropToken
    default:
        return Retry
    }
}

// Gateway: murmur-push. Input is a device ID only; the token lookup happens
// here, so the relay never handles push tokens. Wakes are coalesced per device
// (one per CoalesceWindow).
type Gateway struct {
    Devices        *Registry
    APNs           *APNs
    FCM            *FCM
    CoalesceWindow time.Duration
    Clock          func() time.Time
    mu             sync.Mutex
    last           map[string]time.Time
}

func (g *Gateway) Wake(device string) Outcome {
    g.mu.Lock()
    now := g.Clock()
    if t, ok := g.last[device]; ok && now.Sub(t) < g.CoalesceWindow {
        g.mu.Unlock()
        // a wakeup is already on its way; the app fetches everything queued
        return Delivered
    }
    g.last[device] = now
    g.mu.Unlock()
    d, ok := g.Devices.Get(device)
    if !ok || d.PushToken == "" || !d.RevokedAt.IsZero() {
        // nothing to wake; the device fetches when it next opens
        return Delivered
    }
    var out Outcome
    switch d.Platform {
    case "ios":
        out = g.APNs.Send(d.PushToken)
    case "android":
        out = g.FCM.Send(d.PushToken)
    }
    if out == DropToken {
        g.Devices.SetPushToken(device, "")
    }
    return out
}

// small helpers shared by the services
func randRead(b []byte) { rand.Read(b) }
