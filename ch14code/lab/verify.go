// verify.go
// Listing 14.4 — Go: the checks a WebAuthn library makes, written out with the standard library
// so the lab can run them. (Production code uses a maintained library: Listing 14.3.)
// Supports what Murmur accepts: ES256 credentials, "none" attestation, required UV.
package main

import (
       "bytes"
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/sha256"
       "encoding/base64"
       "encoding/binary"
       "encoding/json"
       "errors"
       "fmt"
       "math/big"
       "sync"
       "time"
)

var b64 = base64.RawURLEncoding

const (
       flagUP = 0x01 // user present
       flagUV = 0x04 // user verified (biometric / PIN)
       flagBE = 0x08 // backup eligible (a syncable passkey)
       flagBS = 0x10 // backup state (currently synced)
       flagAT = 0x40 // attested credential data included
)

type RP struct {
       ID      string          // "murmur.example"
       Origins map[string]bool // web origin + native app origins (Android apk-key-hash)
}

// ---- challenges: random, single use, short-lived, bound to the ceremony ----
type Challenges struct {
       mu sync.Mutex
       m  map[string]challengeRec
}
type challengeRec struct {
       exp  time.Time
       kind string // "webauthn.create" | "webauthn.get"
       user string // registration: the account being registered
}

func NewChallenges() *Challenges { return &Challenges{m: map[string]challengeRec{}} }
func (c *Challenges) Put(ch, kind, user string, exp time.Time) {
       c.mu.Lock()
       c.m[ch] = challengeRec{exp, kind, user}
       c.mu.Unlock()
}
func (c *Challenges) take(ch, kind string, now time.Time) (challengeRec, bool) {
       c.mu.Lock()
       defer c.mu.Unlock()
       r, ok := c.m[ch]
       delete(c.m, ch)
       return r, ok && r.kind == kind && now.Before(r.exp)
}

type Credential struct {
       ID        []byte
       User      string
       Pub       *ecdsa.PublicKey
       SignCount uint32
       BE, BS    bool
}

type clientData struct {
       Type        string `json:"type"`
       Challenge   string `json:"challenge"`
       Origin      string `json:"origin"`
       CrossOrigin bool   `json:"crossOrigin"`
}

func (rp RP) checkClientData(raw []byte, wantType string, chs *Challenges, now time.Time) (challengeRec, error) {
       var cd clientData
       if json.Unmarshal(raw, &cd) != nil {
              return challengeRec{}, errors.New("bad clientDataJSON")
       }
       if cd.Type != wantType {
              return challengeRec{}, fmt.Errorf("type %q", cd.Type)
       }
       // ORIGIN BINDING: the browser/OS wrote this, not the page. A phishing site cannot change it.
       if !rp.Origins[cd.Origin] || cd.CrossOrigin {
              return challengeRec{}, fmt.Errorf("origin %q not allowed", cd.Origin)
       }
       rec, ok := chs.take(cd.Challenge, wantType, now)
       if !ok {
              return challengeRec{}, errors.New("challenge unknown, expired or already used")
       }
       return rec, nil
}

func (rp RP) checkAuthData(ad []byte, requireUV bool) (flags byte, count uint32, err error) {
       if len(ad) < 37 {
              return 0, 0, errors.New("authData too short")
       }
       want := sha256.Sum256([]byte(rp.ID))
       if !bytes.Equal(ad[:32], want[:]) { // the authenticator scoped the key to THIS RP ID
              return 0, 0, errors.New("rpIdHash mismatch")
       }
       flags = ad[32]
       if flags&flagUP == 0 {
              return 0, 0, errors.New("user not present")
       }
       if requireUV && flags&flagUV == 0 {
              return 0, 0, errors.New("user not verified (UV flag clear)")
       }
       if flags&flagBS != 0 && flags&flagBE == 0 {
              return 0, 0, errors.New("invalid flags: BS without BE")
       }
       return flags, binary.BigEndian.Uint32(ad[33:37]), nil
}

// FinishRegistration verifies navigator.credentials.create() output.
func (rp RP) FinishRegistration(clientDataJSON, attObj []byte, chs *Challenges, now time.Time) (*Credential, error) {
       rec, err := rp.checkClientData(clientDataJSON, "webauthn.create", chs, now)
       if err != nil {
              return nil, err
       }
       v, _, err := cborDecode(attObj)
       if err != nil {
              return nil, err
       }
       m, _ := v.(map[any]any)
       if m["fmt"] != "none" { // Murmur: consumer passkeys, no attestation requested (§14.2)
              return nil, fmt.Errorf("attestation format %v not accepted", m["fmt"])
       }
       ad, _ := m["authData"].([]byte)
       flags, count, err := rp.checkAuthData(ad, true)
       if err != nil {
              return nil, err
       }
       if flags&flagAT == 0 || len(ad) < 55 {
              return nil, errors.New("no attested credential data")
       }
       idLen := int(binary.BigEndian.Uint16(ad[53:55])) // after rpIdHash(32) flags(1) count(4) aaguid(16)
       if len(ad) < 55+idLen {
              return nil, errors.New("truncated credential id")
       }
       credID := ad[55 : 55+idLen]
       ck, _, err := cborDecode(ad[55+idLen:])
       if err != nil {
              return nil, err
       }
       pub, err := coseES256(ck)
       if err != nil {
              return nil, err
       }
       return &Credential{ID: credID, User: rec.user, Pub: pub, SignCount: count,
              BE: flags&flagBE != 0, BS: flags&flagBS != 0}, nil
}

// COSE_Key: {1: kty=2 (EC2), 3: alg=-7 (ES256), -1: crv=1 (P-256), -2: x, -3: y}
func coseES256(v any) (*ecdsa.PublicKey, error) {
       m, ok := v.(map[any]any)
       if !ok || m[int64(1)] != int64(2) || m[int64(3)] != int64(-7) || m[int64(-1)] != int64(1) {
              return nil, errors.New("only ES256 P-256 credentials accepted")
       }
       x, _ := m[int64(-2)].([]byte)
       y, _ := m[int64(-3)].([]byte)
       X, Y := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
       if len(x) != 32 || len(y) != 32 || !elliptic.P256().IsOnCurve(X, Y) {
              return nil, errors.New("bad public key")
       }
       return &ecdsa.PublicKey{Curve: elliptic.P256(), X: X, Y: Y}, nil
}

type AssertResult struct {
       Cred         *Credential
       UV           bool
       CloneWarning bool
}

// FinishLogin verifies navigator.credentials.get() output. The credential is looked up by the
// ID the client returned; for discoverable login, userHandle then names the account.
func (rp RP) FinishLogin(store map[string]*Credential, credID, clientDataJSON, authData, sig []byte,
       chs *Challenges, requireUV bool, now time.Time) (*AssertResult, error) {
       cred, ok := store[string(credID)]
       if !ok {
              return nil, errors.New("unknown credential")
       }
       if _, err := rp.checkClientData(clientDataJSON, "webauthn.get", chs, now); err != nil {
              return nil, err
       }
       flags, count, err := rp.checkAuthData(authData, requireUV)
       if err != nil {
              return nil, err
       }
       // Signature over authenticatorData ‖ SHA-256(clientDataJSON): covers origin, challenge, flags.
       h := sha256.Sum256(clientDataJSON)
       signed := sha256.Sum256(append(append([]byte{}, authData...), h[:]...))
       if !ecdsa.VerifyASN1(cred.Pub, signed[:], sig) { // WebAuthn signatures are DER, unlike JWS
              return nil, errors.New("bad signature")
       }
       res := &AssertResult{Cred: cred, UV: flags&flagUV != 0}
       // Counter: synced passkeys usually report 0. Only a NON-ZERO counter that fails to grow is
       // evidence of a cloned authenticator.
       if count != 0 || cred.SignCount != 0 {
              if count <= cred.SignCount {
                     res.CloneWarning = true
              } else {
                     cred.SignCount = count
              }
       }
       cred.BS = flags&flagBS != 0
       return res, nil
}
