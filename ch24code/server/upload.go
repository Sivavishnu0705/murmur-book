// upload.go
// Listing 24.1 — Go: account-authenticated identity key upload that binds the identity key,
// the device ID, the session and the TLS channel together with signatures.
//
//     statement = Framed("murmur/v1/identity-key-upload",
//                        account, device_id, identity_key, dpop_jkt, tls_exporter, issued_at)
//     sig_dpop  = ECDSA-P256 by the device's DPoP key      → this SESSION/DEVICE authorizes it
//     sig_ik    = XEdDSA by the NEW identity key           → the uploader POSSESSES that key
//
// Each binding stops a different attack (§24.3): the access token says who and what scope;
// jkt ties the token to the device's hardware key; the exporter ties the statement to THIS TLS
// connection; the identity-key signature stops uploading someone else's key; the context label
// stops signatures made for any other purpose.
package main

import (
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/sha256"
       "crypto/subtle"
       "encoding/base64"
       "encoding/binary"
       "encoding/json"
       "errors"
       "fmt"
       "math/big"
       "net/http"
       "strconv"
       "sync"
       "time"
)

const uploadLabel = "murmur/v1/identity-key-upload"
const exporterLabel = "EXPORTER-murmur-key-upload"

type Token struct { // what murmur-api learns from validating the access token (Ch 10, 13)
       Account, Device, Jkt string
       Scopes               []string
       Acr                  string
       AuthTime             time.Time
}

type UploadBody struct {
       Account, Device string
       IdentityKey     []byte // X25519 public key (Ch 18)
       DPoPPub         []byte // uncompressed P-256 point
       IssuedAt        int64
       SigDPoP         []byte // ASN.1 ECDSA over SHA-256(statement)
       SigIK           []byte // XEdDSA over statement
}

func statement(b *UploadBody, exporter []byte) []byte {
       ts := binary.BigEndian.AppendUint64(nil, uint64(b.IssuedAt))
       return Framed(uploadLabel, []byte(b.Account), []byte(b.Device), b.IdentityKey,
              []byte(jktOf(b.DPoPPub)), exporter, ts)
}

// jktOf: RFC 7638 thumbprint of a P-256 key (Ch 13).
func jktOf(uncompressed []byte) string {
       if len(uncompressed) != 65 {
              return ""
       }
       e := base64.RawURLEncoding.EncodeToString
       canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, e(uncompressed[1:33]), e(uncompressed[33:]))
       h := sha256.Sum256([]byte(canon))
       return e(h[:])
}

type KeyServer struct {
       mu     sync.Mutex
       Tokens map[string]Token
       Keys   map[string][]byte // device → current identity key (published after the AIK-signed list, Ch 20)
       Now    func() time.Time
}

var errStepUp = errors.New(`401 insufficient_user_authentication (acr_values="phr", max_age="300")`)

func has(xs []string, s string) bool {
       for _, x := range xs {
              if x == s {
                     return true
              }
       }
       return false
}

func (s *KeyServer) check(r *http.Request) error {
       tok, ok := s.Tokens[r.Header.Get("Authorization")]
       if !ok {
              return errors.New("401 invalid_token")
       }
       now := s.Now()
       // 1. Authorization: scope, and a fresh phishing-resistant authentication (Ch 12 §12.8, Ch 14).
       if !has(tok.Scopes, "keys:write") || tok.Acr != "phr" || now.Sub(tok.AuthTime) > 5*time.Minute {
              return errStepUp
       }
       var b UploadBody
       if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
              return errors.New("400 bad body")
       }
       // 2. The statement is about the SAME account and device the token was issued to.
       if b.Account != tok.Account || b.Device != tok.Device {
              return errors.New("403 statement names a different account/device than the session")
       }
       // 3. Session binding: the signing DPoP key is the one the token is bound to (cnf.jkt).
       if subtle.ConstantTimeCompare([]byte(jktOf(b.DPoPPub)), []byte(tok.Jkt)) != 1 {
              return errors.New("401 DPoP key does not match the token's cnf.jkt")
       }
       // 4. Channel binding: the exporter of THIS TLS connection.
       if r.TLS == nil {
              return errors.New("400 TLS required")
       }
       exp, err := r.TLS.ExportKeyingMaterial(exporterLabel, nil, 32)
       if err != nil {
              return errors.New("500 exporter unavailable")
       }
       st := statement(&b, exp)
       x, y := elliptic.Unmarshal(elliptic.P256(), b.DPoPPub)
       if x == nil {
              return errors.New("400 bad DPoP key")
       }
       d := sha256.Sum256(st)
       if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, d[:], b.SigDPoP) {
              return errors.New("401 statement not signed for this TLS connection by the session's key")
       }
       // 5. Proof of possession of the new identity key, under the SAME labeled statement.
       var ik [32]byte
       var sig [64]byte
       if len(b.IdentityKey) != 32 || len(b.SigIK) != 64 {
              return errors.New("400 bad identity key or signature")
       }
       copy(ik[:], b.IdentityKey)
       copy(sig[:], b.SigIK)
       if !VerifyXEdDSA(ik, st, sig) {
              return errors.New("401 no proof of possession of the identity key")
       }
       // 6. Freshness.
       if d := now.Unix() - b.IssuedAt; d < -60 || d > 60 {
              return errors.New("401 statement too old or from the future")
       }
       s.mu.Lock()
       s.Keys[b.Device] = b.IdentityKey
       s.mu.Unlock()
       return nil
}

// ServeHTTP maps each error to its status: every message in check starts with its HTTP code
// ("400 …", "401 …", "403 …"), so the status line and the body always agree.
func (s *KeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
       if err := s.check(r); err != nil {
              code := http.StatusUnauthorized
              if msg := err.Error(); len(msg) > 3 && msg[3] == ' ' {
                     if c, convErr := strconv.Atoi(msg[:3]); convErr == nil && c >= 400 && c < 600 {
                            code = c
                     }
              }
              http.Error(w, err.Error(), code)
              return
       }
       w.WriteHeader(http.StatusNoContent)
}

// NaiveRotate is the ⚠️ INSECURE variant used in the lab: "rotate identity key to K" is
// authorized by Sig(old IK, Encode(K)) — the SAME unlabeled format X3DH uses for SPK signatures.
func NaiveRotate(keys map[string][]byte, device string, newKey []byte, sig [64]byte) error {
       var old [32]byte
       copy(old[:], keys[device])
       if !VerifyXEdDSA(old, append([]byte{0x05}, newKey...), sig) {
              return errors.New("bad signature")
       }
       keys[device] = newKey
       return nil
}

var _ = big.NewInt // (math/big is used by xeddsa.go)
