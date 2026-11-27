// directory.go (Chapter 27's Listing 27.4; Chapter 28 adds the duplicate-ID
// answer in PutPrekeys) Listing 27.4 — Go: key directory handlers. Uploads are
// verified before they are stored (sizes, XEdDSA signatures by the device's own
// identity key, per-kind caps); bundle fetches are rate-limited per requesting
// device and consume one-time prekeys atomically through KeyStore.ClaimBundle
// (Listing 27.5); signed device lists are accepted only as exact signed bytes
// that re-encode canonically, with a newer version, listing only active
// devices.
package main

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/binary"
    "encoding/json"
    "errors"
    "net/http"
    "sync"
    "time"
)

const (
    ecKeyLen, pqKeyLen = 32, 1568 // X25519; ML-KEM-1024 encapsulation key
    maxPerUpload       = 100
    maxStoredOneTime   = 200
    lowWater           = 20 // Ch 18: below this the owner is woken to replenish
)

type Directory struct {
    Keys     KeyStore
    Devices  *Registry
    Limiter  *Limiter
    Clock    func() time.Time
    // wake the device (content-free push) to upload more prekeys
    OnLow    func(device string)
    mu       sync.Mutex
    aiks     map[string]ed25519.PublicKey
    lists    map[string][]byte // account → current signed list bytes ‖ sig
    versions map[string]uint64
    // device → identity key (cache of KeyStore, for signature checks)
    iks      map[string][]byte
}

func NewDirectory(ks KeyStore, reg *Registry,
    clock func() time.Time) *Directory {
    return &Directory{Keys: ks, Devices: reg, Limiter: NewLimiter(10),
        Clock: clock, OnLow: func(string) {},
        aiks: map[string]ed25519.PublicKey{}, lists: map[string][]byte{},
        versions: map[string]uint64{}, iks: map[string][]byte{}}
}

func readJSON(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
    if json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(v) != nil {
        writeErr(w, 400, "MALFORMED", false)
        return false
    }
    return true
}

// POST /v1/keys/identity (scope keys:write → step-up). Murmur's rule: a
// device's identity key never changes; a new identity is a new device
// (enrollment, device list, KT entry). Production also requires the Ch 24
// binding (DPoP key + TLS exporter + XEdDSA PoP).
func (d *Directory) PutIdentity(w http.ResponseWriter, r *http.Request) {
    c := CallerFrom(r)
    var req struct {
        IdentityKey []byte `json:"identity_key"`
    }
    if !readJSON(w, r, 4<<10, &req) || len(req.IdentityKey) != ecKeyLen {
        writeErr(w, 400, "MALFORMED", false)
        return
    }
    d.mu.Lock()
    defer d.mu.Unlock()
    if _, exists := d.iks[c.Device]; exists {
        writeErr(w, 409, "CONFLICT", false)
        return
    }
    if err := d.Keys.PutIdentity(r.Context(), c.Account, c.Device,
        req.IdentityKey); err != nil {
        writeErr(w, 503, "UNAVAILABLE", true)
        return
    }
    d.iks[c.Device] = req.IdentityKey
    w.WriteHeader(204)
}

type prekeyUpload struct {
    SignedPrekey *PreKey  `json:"signed_prekey,omitempty"` // weekly rotation
    PQLastResort *PreKey  `json:"pq_last_resort,omitempty"`
    OneTime      []PreKey `json:"one_time,omitempty"`
    PQOneTime    []PreKey `json:"pq_one_time,omitempty"`
}

// PUT /v1/keys/prekeys  (scope prekeys:write; routine, so no step-up).
func (d *Directory) PutPrekeys(w http.ResponseWriter, r *http.Request) {
    c := CallerFrom(r)
    var u prekeyUpload
    if !readJSON(w, r, 512<<10, &u) {
        return
    }
    d.mu.Lock()
    ik, ok := d.iks[c.Device]
    d.mu.Unlock()
    if !ok {
        writeErr(w, 409, "CONFLICT", false) // identity first
        return
    }
    // XEdDSA(IK, typ ‖ pub), Ch 18
    signedOK := func(k *PreKey, typ byte, size int) bool {
        var x [32]byte
        var s [64]byte
        if k == nil || len(k.Pub) != size || len(k.Sig) != 64 {
            return false
        }
        copy(x[:], ik)
        copy(s[:], k.Sig)
        return VerifyXEdDSA(x, append([]byte{typ}, k.Pub...), s)
    }
    if (u.SignedPrekey != nil && !signedOK(u.SignedPrekey, 0x05, ecKeyLen)) ||
        (u.PQLastResort != nil && !signedOK(u.PQLastResort, 0x08, pqKeyLen)) ||
        len(u.OneTime) > maxPerUpload || len(u.PQOneTime) > maxPerUpload {
        writeErr(w, 400, "MALFORMED", false)
        return
    }
    for _, k := range u.OneTime {
        if len(k.Pub) != ecKeyLen || k.Sig != nil {
            writeErr(w, 400, "MALFORMED", false)
            return
        }
    }
    for i := range u.PQOneTime {
        // a server-swappable KEM key breaks PQXDH
        if !signedOK(&u.PQOneTime[i], 0x08, pqKeyLen) {
            writeErr(w, 400, "MALFORMED", false)
            return
        }
    }
    ctx := r.Context()
    for kind, add := range map[string][]PreKey{"ec": u.OneTime,
        "pq": u.PQOneTime} {
        if n, _ := d.Keys.CountOneTime(ctx, c.Device,
            kind); n+len(add) > maxStoredOneTime {
            writeErr(w, 400, "MALFORMED", false)
            return
        }
    }
    var err error
    if u.SignedPrekey != nil {
        err = errors.Join(err, d.Keys.PutSigned(ctx, c.Device, "ec",
            *u.SignedPrekey))
    }
    if u.PQLastResort != nil {
        err = errors.Join(err, d.Keys.PutSigned(ctx, c.Device, "pq",
            *u.PQLastResort))
    }
    err = errors.Join(err, d.Keys.AddOneTime(ctx, c.Device, "ec", u.OneTime),
        d.Keys.AddOneTime(ctx, c.Device, "pq", u.PQOneTime))
    // Chapter 28: an ID can be stored only once
    if errors.Is(err, ErrDuplicateKey) {
        writeErr(w, 409, "CONFLICT", false)
        return
    }
    // the client retries the whole upload; key IDs make retries idempotent
    if err != nil {
        writeErr(w, 503, "UNAVAILABLE", true)
        return
    }
    w.WriteHeader(204)
}

// GET /v1/keys/bundle/{device} (scope messages:send). Consumes keys:
// rate-limited per caller.
func (d *Directory) GetBundle(w http.ResponseWriter, r *http.Request) {
    c := CallerFrom(r)
    target := r.PathValue("device")
    // 10/min per requesting device (Ch 18 §18.6)
    if !d.Limiter.Allow(c.Device, d.Clock()) {
        w.Header().Set("Retry-After", "60")
        writeErr(w, 429, "RATE_LIMITED", true)
        return
    }
    dev, ok := d.Devices.Get(target)
    if !ok || !dev.RevokedAt.IsZero() {
        writeErr(w, 404, "NOT_FOUND", false) // uniform: absent, revoked
        return
    }
    b, err := d.Keys.ClaimBundle(r.Context(), target)
    if errors.Is(err, ErrNotFound) {
        writeErr(w, 404, "NOT_FOUND", false)
        return
    } else if err != nil {
        writeErr(w, 503, "UNAVAILABLE", true)
        return
    }
    if n, _ := d.Keys.CountOneTime(context.Background(), target,
        "ec"); n < lowWater {
        d.OnLow(target)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(b)
}

// ── account identity key and signed device lists (Ch 20) ──

// PUT /v1/aik (scope keys:write → step-up): first device only; later changes go
// through KT.
func (d *Directory) PutAIK(w http.ResponseWriter, r *http.Request) {
    c := CallerFrom(r)
    var req struct {
        AIK []byte `json:"aik"`
    }
    if !readJSON(w, r, 1<<10, &req) || len(req.AIK) != ed25519.PublicKeySize {
        writeErr(w, 400, "MALFORMED", false)
        return
    }
    d.mu.Lock()
    defer d.mu.Unlock()
    if _, ok := d.aiks[c.Account]; ok {
        writeErr(w, 409, "CONFLICT", false)
        return
    }
    d.aiks[c.Account] = req.AIK
    w.WriteHeader(204)
}

// parseDeviceList decodes Ch 20's canonical encoding and REQUIRES that
// re-encoding gives the same bytes: no trailing data, no unsorted entries, no
// second encoding of one list.
func parseDeviceList(b []byte) (account string, version uint64,
    devs map[string][]byte, err error) {
    bad := errors.New("malformed device list")
    rd := bytes.NewReader(b)
    str := func() ([]byte, error) {
        var n uint32
        if binary.Read(rd, binary.BigEndian, &n) != nil || int(n) > rd.Len() {
            return nil, bad
        }
        s := make([]byte, n)
        rd.Read(s)
        return s, nil
    }
    label, err := str()
    if err != nil || string(label) != "murmur device list v1" {
        return "", 0, nil, bad
    }
    acct, err := str()
    if err != nil || binary.Read(rd, binary.BigEndian, &version) != nil {
        return "", 0, nil, bad
    }
    var count uint32
    if binary.Read(rd, binary.BigEndian, &count) != nil || count > MaxDevices {
        return "", 0, nil, bad
    }
    devs, prev := map[string][]byte{}, ""
    for i := uint32(0); i < count; i++ {
        id, err := str()
        ik := make([]byte, 32)
        if err != nil || string(id) <= prev && i > 0 {
            // must be strictly sorted: canonical and duplicate-free
            return "", 0, nil, bad
        }
        if n, _ := rd.Read(ik); n != 32 {
            return "", 0, nil, bad
        }
        var added int64
        if _, err := str(); err != nil || binary.Read(rd, binary.BigEndian,
            &added) != nil {
            return "", 0, nil, bad
        }
        devs[string(id)], prev = ik, string(id)
    }
    if rd.Len() != 0 {
        return "", 0, nil, bad
    }
    return string(acct), version, devs, nil
}

// PUT /v1/devicelist (scope keys:write → step-up). Body: the signed bytes,
// verbatim, and sig.
func (d *Directory) PutDeviceList(w http.ResponseWriter, r *http.Request) {
    c := CallerFrom(r)
    var req struct{ Encoded, Signature []byte }
    if !readJSON(w, r, 16<<10, &req) {
        return
    }
    acct, version, devs, err := parseDeviceList(req.Encoded)
    d.mu.Lock()
    defer d.mu.Unlock()
    aik, ok := d.aiks[c.Account]
    switch {
    case err != nil || acct != c.Account || !ok:
        writeErr(w, 400, "MALFORMED", false)
        return
    // over the exact bytes (rule E1)
    case !ed25519.Verify(aik, req.Encoded, req.Signature):
        writeErr(w, 400, "MALFORMED", false)
        return
    case version <= d.versions[acct]:
        writeErr(w, 409, "CONFLICT", false) // rollback
        return
    }
    // the server refuses lists naming revoked or foreign devices
    for id, ik := range devs {
        dev, ok := d.Devices.Get(id)
        if !ok || dev.Account != c.Account || !dev.RevokedAt.IsZero() ||
            !bytes.Equal(d.iks[id], ik) {
            writeErr(w, 400, "MALFORMED", false)
            return
        }
    }
    d.lists[acct], d.versions[acct] = append(append([]byte{}, req.Encoded...),
        req.Signature...), version
    // Production: append (account, version, H(list)) to the key transparency
    // log (Ch 20 §20.5).
    w.WriteHeader(204)
}

// GET /v1/devicelist/{account} (scope messages:send) — the signed bytes;
// clients verify.
func (d *Directory) GetDeviceList(w http.ResponseWriter, r *http.Request) {
    d.mu.Lock()
    l, ok := d.lists[r.PathValue("account")]
    d.mu.Unlock()
    if !ok {
        writeErr(w, 404, "NOT_FOUND", false)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string][]byte{"encoded": l[:len(l)-64],
        "signature": l[len(l)-64:]})
}

// Forget drops the cached identity key of a revoked device.
func (d *Directory) Forget(device string) {
    d.mu.Lock()
    delete(d.iks, device)
    d.mu.Unlock()
}
