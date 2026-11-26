// keypackages.go
// Listing 30.4 — Go: the KeyPackage directory (added in Chapter 30). Like one-time prekeys
// (Listing 27.4): uploads are bounded, claims are atomic and rate-limited, and each device keeps
// ONE last-resort KeyPackage that is served (not deleted) only when the others run out. The
// server checks framing and size only; clients verify the KeyPackage signature, its lifetime,
// and the Authentication Service binding of its credential (Listing 30.1).
package main

import (
       "bytes"
       "encoding/binary"
       "encoding/json"
       "net/http"
       "sync"
       "time"
)

const (
       maxKeyPackages  = 100
       maxKeyPackageSz = 4 << 10
       wireKeyPackage  = 5 // RFC 9420 WireFormat mls_key_package
)

type KeyPackages struct {
       mu         sync.Mutex
       single     map[string][][]byte // device → single-use KeyPackages (oldest first)
       lastResort map[string][]byte
       Devices    *Registry
       Limiter    *Limiter
       Clock      func() time.Time
}

func validKeyPackageFraming(b []byte) bool {
       if len(b) < 4 || len(b) > maxKeyPackageSz {
              return false
       }
       var version, wire uint16
       r := bytes.NewReader(b)
       binary.Read(r, binary.BigEndian, &version)
       binary.Read(r, binary.BigEndian, &wire)
       return version == 1 && wire == wireKeyPackage
}

// PUT /v1/mls/keypackages  (scope prekeys:write): {key_packages: [...], last_resort?: bytes}
func (k *KeyPackages) Upload(w http.ResponseWriter, r *http.Request) {
       c := CallerFrom(r)
       var q struct {
              KeyPackages [][]byte `json:"key_packages"`
              LastResort  []byte   `json:"last_resort"`
       }
       if !readJSON(w, r, 512<<10, &q) || len(q.KeyPackages) > maxKeyPackages {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       for _, kp := range q.KeyPackages {
              if !validKeyPackageFraming(kp) {
                     writeErr(w, 400, "MALFORMED", false)
                     return
              }
       }
       if q.LastResort != nil && !validKeyPackageFraming(q.LastResort) {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       k.mu.Lock()
       defer k.mu.Unlock()
       if len(k.single[c.Device])+len(q.KeyPackages) > maxKeyPackages {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       k.single[c.Device] = append(k.single[c.Device], q.KeyPackages...)
       if q.LastResort != nil {
              k.lastResort[c.Device] = q.LastResort
       }
       w.WriteHeader(204)
}

// GET /v1/mls/keypackage/{device}  (scope messages:send): claim one, atomically.
func (k *KeyPackages) Claim(w http.ResponseWriter, r *http.Request) {
       c := CallerFrom(r)
       target := r.PathValue("device")
       if !k.Limiter.Allow(c.Device, k.Clock()) {
              writeErr(w, 429, "RATE_LIMITED", true)
              return
       }
       if d, ok := k.Devices.Get(target); !ok || !d.RevokedAt.IsZero() {
              writeErr(w, 404, "NOT_FOUND", false)
              return
       }
       k.mu.Lock()
       var kp []byte
       lastResort := false
       if l := k.single[target]; len(l) > 0 {
              kp, k.single[target] = l[0], l[1:] // taken and removed under one lock
       } else if lr, ok := k.lastResort[target]; ok {
              kp, lastResort = lr, true
       }
       remaining := len(k.single[target])
       k.mu.Unlock()
       if kp == nil {
              writeErr(w, 404, "NOT_FOUND", false)
              return
       }
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(map[string]any{"key_package": kp, "last_resort": lastResort, "remaining": remaining})
}

// GET /v1/mls/keypackages/count  (scope prekeys:write)
func (k *KeyPackages) Count(w http.ResponseWriter, r *http.Request) {
       k.mu.Lock()
       n, lr := len(k.single[CallerFrom(r).Device]), k.lastResort[CallerFrom(r).Device] != nil
       k.mu.Unlock()
       json.NewEncoder(w).Encode(map[string]any{"count": n, "last_resort": lr})
}

// Forget is part of the revocation cascade (Listing 27.3).
func (k *KeyPackages) Forget(device string) {
       k.mu.Lock()
       delete(k.single, device)
       delete(k.lastResort, device)
       k.mu.Unlock()
}
