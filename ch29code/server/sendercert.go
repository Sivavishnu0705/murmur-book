// sendercert.go
// Listing 29.1 — Go: sender certificates for sealed sender (added in Chapter 29). murmur-auth
// signs (account, device, identity key, expiry) for an AUTHENTICATED device; the recipient
// verifies the signature with the public key compiled into the app, checks the expiry, and
// checks that the identity key is the one its Double Ratchet session with that device uses.
// The signature covers Framed("murmur sender cert v1", …) (Ch 24), never a JSON or protobuf
// encoding (spec rule E1).
package main

import (
       "crypto/ed25519"
       "crypto/rand"
       "encoding/binary"
       "encoding/json"
       "net/http"
       "time"
)

const senderCertLifetime = 24 * time.Hour

type SenderCerts struct {
       Key       ed25519.PrivateKey
       Directory *Directory
       Clock     func() time.Time
}

func newEd25519() (ed25519.PrivateKey, error) {
       _, k, err := ed25519.GenerateKey(rand.Reader)
       return k, err
}

// IdentityKey returns a device's uploaded identity key. Listing 27.4 caches them in d.iks.
func (d *Directory) IdentityKey(device string) ([]byte, bool) {
       d.mu.Lock()
       defer d.mu.Unlock()
       ik, ok := d.iks[device]
       return ik, ok
}

func framed(label string, fields ...[]byte) []byte { // Listing 24.2's Framed, byte for byte
       b := binary.BigEndian.AppendUint16(nil, uint16(len(label)))
       b = append(b, label...)
       for _, f := range fields {
              b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
              b = append(b, f...)
       }
       return b
}

// GET /v1/sender-certificate  (scope messages:send)
func (s *SenderCerts) Issue(w http.ResponseWriter, r *http.Request) {
       c := CallerFrom(r)
       ik, ok := s.Directory.IdentityKey(c.Device)
       if !ok {
              writeErr(w, 409, "CONFLICT", false) // upload the identity key first
              return
       }
       exp := s.Clock().Add(senderCertLifetime).Unix()
       msg := framed("murmur sender cert v1", []byte(c.Account), []byte(c.Device), ik, binary.BigEndian.AppendUint64(nil, uint64(exp)))
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(map[string]any{"account": c.Account, "device": c.Device, "identity_key": ik,
              "expires_unix": exp, "signature": ed25519.Sign(s.Key, msg)})
}
