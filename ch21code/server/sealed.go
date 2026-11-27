// sealed.go
// Sealed-sender envelopes (client side, used by the lab): the sender's identity
// travels INSIDE the encryption, as a server-issued sender certificate; the
// outer envelope names only the recipient device. Simplified from Signal's
// design: one ephemeral X25519 DH to the recipient's identity key, HKDF,
// AES-256-GCM. Inner content (already Double-Ratchet encrypted) is padded.
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/ed25519"
    "crypto/hkdf"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/json"
    "errors"
    "time"
)

// SenderCert is issued by murmur-auth to an AUTHENTICATED device, valid for a
// day. The relay never sees it in the clear; the recipient verifies it against
// the server's cert-signing key.
type SenderCert struct {
    Account, Device string
    // sender device's X25519 identity key (binds the inner DR session)
    IdentityKey     []byte
    Expires         int64
    Sig             []byte // Ed25519 by the server's sender-certificate key
}

func (c *SenderCert) signed() []byte {
    b, _ := json.Marshal([]any{"murmur sender cert v1", c.Account, c.Device,
        c.IdentityKey, c.Expires})
    return b
}

func IssueCert(serverKey ed25519.PrivateKey, account, device string, ik []byte,
    now time.Time) SenderCert {
    c := SenderCert{Account: account, Device: device, IdentityKey: ik,
        Expires: now.Add(24 * time.Hour).Unix()}
    c.Sig = ed25519.Sign(serverKey, c.signed())
    return c
}

// Pad to 160-byte buckets (§21.6): sizes reveal only a coarse range.
func pad(b []byte) []byte {
    n := (len(b) + 4 + 159) / 160 * 160
    out := make([]byte, n)
    binary.BigEndian.PutUint32(out, uint32(len(b)))
    copy(out[4:], b)
    return out
}

func unpad(b []byte) ([]byte, error) {
    if len(b) < 4 || int(binary.BigEndian.Uint32(b)) > len(b)-4 {
        return nil, errors.New("bad padding")
    }
    return b[4 : 4+binary.BigEndian.Uint32(b)], nil
}

func sealKey(shared, eph, recipient []byte) cipher.AEAD {
    k, _ := hkdf.Key(sha256.New, shared, append(append([]byte{}, eph...),
        recipient...), "murmur sealed sender v1", 32)
    blk, _ := aes.NewCipher(k)
    g, _ := cipher.NewGCM(blk)
    return g
}

// Seal: only the recipient device (holder of recipientIK's private key) can
// learn the sender.
func Seal(recipientIK *ecdh.PublicKey, cert SenderCert, inner []byte) []byte {
    eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
    shared, _ := eph.ECDH(recipientIK)
    body, _ := json.Marshal(struct {
        Cert  SenderCert
        Inner []byte
    }{cert, inner})
    g := sealKey(shared, eph.PublicKey().Bytes(), recipientIK.Bytes())
    // key is fresh per envelope (new ephemeral), so a zero nonce is safe
    nonce := make([]byte, 12)
    return append(eph.PublicKey().Bytes(), g.Seal(nil, nonce, pad(body),
        nil)...)
}

// Unseal runs on the recipient: decrypt, verify the sender certificate, and
// check that the certificate's identity key is the one the inner Double Ratchet
// session belongs to (not shown).
func Unseal(recipient *ecdh.PrivateKey, serverPub ed25519.PublicKey,
    blob []byte, now time.Time) (*SenderCert, []byte, error) {
    if len(blob) < 32 {
        return nil, nil, errors.New("short envelope")
    }
    ephPub, err := ecdh.X25519().NewPublicKey(blob[:32])
    if err != nil {
        return nil, nil, err
    }
    shared, err := recipient.ECDH(ephPub)
    if err != nil {
        return nil, nil, err
    }
    pt, err := sealKey(shared, blob[:32],
        recipient.PublicKey().Bytes()).Open(nil, make([]byte, 12), blob[32:],
        nil)
    if err != nil {
        return nil, nil, errors.New("envelope does not decrypt")
    }
    body, err := unpad(pt)
    if err != nil {
        return nil, nil, err
    }
    var m struct {
        Cert  SenderCert
        Inner []byte
    }
    if json.Unmarshal(body, &m) != nil {
        return nil, nil, errors.New("bad envelope body")
    }
    if !ed25519.Verify(serverPub, m.Cert.signed(),
        m.Cert.Sig) || now.Unix() > m.Cert.Expires {
        return nil, nil, errors.New("sender certificate invalid or expired")
    }
    return &m.Cert, m.Inner, nil
}
