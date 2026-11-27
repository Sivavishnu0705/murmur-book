// registry.go
// Listing 27.3 — Go: device registry — enrollment with attestation
// verification, device-scoped sessions and revocation. Enrollment happens at
// murmur-auth's token endpoint (the first token for a new DPoP key creates the
// device); murmur-api and murmur-relay consult Active() through the revocation
// feed. Revocation cascades to everything the server holds for the device.
package main

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "encoding/hex"
    "errors"
    "math/big"
    "sync"
    "time"
)

// Ch 20: fan-out cost and the device-list UI both assume a small set
const MaxDevices = 8

// Verdict is what platform attestation proves (Ch 9 §9.6). Production
// verifiers: Android key attestation chain + Play Integrity; iOS App Attest.
// They are interfaces here so the policy below is the same for both and for the
// lab's stand-in.
type Verdict struct {
    // package name + signing cert digest, or Team ID + bundle ID
    AppID           string
    // Android: attested key's securityLevel ≥ TEE; iOS: false (see Ch 9)
    KeyInHardware   bool
    // MEETS_DEVICE_INTEGRITY / App Attest counter and environment checks
    DeviceIntegrity bool
}

type AttestationVerifier interface {
    // Verify checks evidence that was produced for exactly this nonce and this
    // public key.
    Verify(evidence []byte, nonce []byte, spki []byte) (Verdict, error)
}

type Device struct {
    ID, Account, Platform, Jkt string
    PushToken                  string // provider token; deleted on revocation
    Enrolled, RevokedAt        time.Time
    Verdict                    Verdict
}

type Registry struct {
    mu        sync.Mutex
    devices   map[string]*Device // device ID → device
    nonces    map[string]time.Time
    Verifiers map[string]AttestationVerifier // "android" | "ios"
    // platform → the only acceptable AppID
    AppIDs    map[string]string
    // cascade hooks: keys, queues, push tokens, KeyPackages
    OnRevoke  []func(d *Device)
    // revocation feed (pub/sub in production)
    Feed      chan string
}

func NewRegistry() *Registry {
    return &Registry{devices: map[string]*Device{},
        nonces: map[string]time.Time{},
        Verifiers: map[string]AttestationVerifier{},
        AppIDs: map[string]string{}, Feed: make(chan string, 64)}
}

// Challenge issues a single-use enrollment nonce (5-minute lifetime).
func (r *Registry) Challenge(now time.Time) []byte {
    n := make([]byte, 32)
    rand.Read(n)
    r.mu.Lock()
    r.nonces[hex.EncodeToString(n)] = now.Add(5 * time.Minute)
    r.mu.Unlock()
    return n
}

type EnrollRequest struct {
    Account, Platform string
    Nonce             []byte
    // from the verified DPoP proof on the token request
    DPoPKey           *ecdsa.PublicKey
    Jkt               string           // its RFC 7638 thumbprint
    // ECDSA(r‖s) over SHA-256("murmur/v1/enroll-pop\0" ‖ nonce ‖ account)
    PoP               []byte
    Attestation       []byte
    // acr=phr within 5 min — required for every device after the first
    StepUpOK          bool
}

var (
    ErrNonce       = errors.New("nonce unknown, used or expired")
    ErrPoP         = errors.New("proof of possession invalid")
    ErrAttestation = errors.New("attestation rejected")
    ErrTooMany     = errors.New("device limit reached")
    ErrStepUp      = errors.New("step-up required to add a device")
)

func (r *Registry) Enroll(q EnrollRequest, now time.Time) (*Device, error) {
    r.mu.Lock()
    defer r.mu.Unlock()
    k := hex.EncodeToString(q.Nonce)
    exp, ok := r.nonces[k]
    delete(r.nonces, k) // single use, even when the rest fails
    if !ok || now.After(exp) {
        return nil, ErrNonce
    }
    d := sha256.Sum256(append(append([]byte("murmur/v1/enroll-pop\x00"),
        q.Nonce...), q.Account...))
    if len(q.PoP) != 64 || !ecdsa.Verify(q.DPoPKey, d[:],
        new(big.Int).SetBytes(q.PoP[:32]), new(big.Int).SetBytes(q.PoP[32:])) {
        return nil, ErrPoP
    }
    v, ok := r.Verifiers[q.Platform]
    if !ok {
        return nil, ErrAttestation
    }
    spki, _ := x509.MarshalPKIXPublicKey(q.DPoPKey)
    verdict, err := v.Verify(q.Attestation, q.Nonce, spki)
    if err != nil || verdict.AppID != r.AppIDs[q.Platform] ||
        !verdict.DeviceIntegrity {
        return nil, ErrAttestation
    }
    active := 0
    for _, x := range r.devices {
        if x.Account == q.Account && x.RevokedAt.IsZero() {
            active++
        }
    }
    if active >= MaxDevices {
        return nil, ErrTooMany
    }
    // the first device has nothing to step up FROM (Ch 15 §15.2)
    if active > 0 && !q.StepUpOK {
        return nil, ErrStepUp
    }
    id := make([]byte, 8)
    rand.Read(id)
    dev := &Device{ID: "dev-" + hex.EncodeToString(id), Account: q.Account,
        Platform: q.Platform,
        Jkt: q.Jkt, Enrolled: now, Verdict: verdict}
    r.devices[dev.ID] = dev
    return dev, nil
}

// Active is called on EVERY API request (Listing 27.2): the device exists,
// belongs to the token's account, is not revoked, and is still bound to the
// presenting DPoP key.
func (r *Registry) Active(account, device, jkt string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    d, ok := r.devices[device]
    return ok && d.Account == account && d.RevokedAt.IsZero() && d.Jkt == jkt
}

func (r *Registry) SetPushToken(device, token string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if d, ok := r.devices[device]; ok {
        d.PushToken = token
    }
}

func (r *Registry) Get(device string) (Device, bool) {
    r.mu.Lock()
    defer r.mu.Unlock()
    d, ok := r.devices[device]
    if !ok {
        return Device{}, false
    }
    return *d, true
}

// Revoke: the caller already passed step-up (scope devices:revoke) and owns
// both devices. The server cannot edit the signed device list — only the AIK
// can (Ch 20) — so it tells the account's other devices to publish a new list
// without the revoked device.
func (r *Registry) Revoke(account, device string, now time.Time) error {
    r.mu.Lock()
    d, ok := r.devices[device]
    if !ok || d.Account != account || !d.RevokedAt.IsZero() {
        r.mu.Unlock()
        // uniform: absent, not yours, or already revoked
        return errors.New("NOT_FOUND")
    }
    d.RevokedAt, d.PushToken = now, ""
    snapshot := *d
    r.mu.Unlock()
    for _, f := range r.OnRevoke {
        f(&snapshot)
    }
    select {
    case r.Feed <- device:
    default: // a full feed must never block revocation; consumers also poll
    }
    return nil
}

// ByJkt finds the active device bound to a DPoP key (token requests for an
// enrolled device).
func (r *Registry) ByJkt(account, jkt string) (Device, bool) {
    r.mu.Lock()
    defer r.mu.Unlock()
    for _, d := range r.devices {
        if d.Account == account && d.Jkt == jkt && d.RevokedAt.IsZero() {
            return *d, true
        }
    }
    return Device{}, false
}

// ByAccount lists all of an account's device IDs (revoked ones included;
// callers filter).
func (r *Registry) ByAccount(account string) []string {
    r.mu.Lock()
    defer r.mu.Unlock()
    var out []string
    for id, d := range r.devices {
        if d.Account == account {
            out = append(out, id)
        }
    }
    return out
}
