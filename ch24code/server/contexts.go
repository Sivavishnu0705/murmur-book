// contexts.go
// Listing 24.2 — Go: Murmur's context-string and domain-separation registry.
// EVERY signature, MAC and KDF in Murmur uses a label from this table, so no
// value produced for one purpose can ever be accepted for another. Labels from
// earlier chapters are kept byte-for-byte (they are in deployed wire formats);
// new ones follow the "murmur/v1/<purpose>" form. The init check rejects
// duplicates and labels that are prefixes of each other.
package main

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "sort"
    "strings"
)

type Use string

const (
    UseSign Use = "signature"
    UseMAC  Use = "mac"
    UseKDF  Use = "kdf-info"
    UseHash Use = "hash/prologue"
)

type Label struct {
    Text, Purpose, Key string
    Use                Use
    Chapter            int
}

var Registry = []Label{
    {"murmur/v1/enroll-pop\x00", "device enrollment proof of possession",
        "device mTLS key", UseSign, 9},
    {"murmur/v1/identity-key-upload",
        "bind new identity key to account, device, session, channel",
        "device identity key + DPoP key", UseSign, 24},
    {"EXPORTER-murmur-key-upload", "TLS exporter label for identity-key upload",
        "TLS connection", UseKDF, 24},
    {"Murmur_X3DH_v1", "X3DH SK derivation", "DH outputs", UseKDF, 18},
    {"Murmur_CURVE25519_SHA-256_ML-KEM-1024", "PQXDH SK derivation",
        "DH outputs + KEM secret", UseKDF, 18},
    {"Murmur_DR_Root_v1", "Double Ratchet root chain", "root key", UseKDF, 19},
    {"Murmur_DR_Msg_v1", "Double Ratchet message key expansion", "message key",
        UseKDF, 19},
    {"murmur pairing SAS v1", "pairing short authentication string",
        "Noise handshake hash", UseKDF, 17},
    {"murmur-pairing/v1|", "Noise prologue for device pairing", "—", UseHash,
        17},
    {"murmur device list v1", "account device list", "AIK", UseSign, 20},
    {"murmur sealed sender v1", "sealed sender envelope key", "ephemeral DH",
        UseKDF, 21},
    {"murmur sender cert v1", "sealed sender certificate", "server cert key",
        UseSign, 21},
    {"murmur delivery token v1", "sealed sender delivery token", "access key",
        UseMAC, 21},
    {"murmur sender key msg v1", "sender-key message key expansion",
        "message key", UseKDF, 22},
    {"murmur group state v1", "admin-signed group state", "AIK", UseSign, 22},
    // XEdDSA SPK signatures (Ch 18) sign Encode(SPK) = 0x05‖key WITHOUT a
    // label, as in X3DH. That is why the identity key must never sign anything
    // else unlabeled: §24.3.
}

func init() {
    texts := make([]string, len(Registry))
    for i, l := range Registry {
        texts[i] = l.Text
    }
    sort.Strings(texts)
    for i := 0; i < len(texts); i++ {
        for j := 0; j < len(texts); j++ {
            if i != j && strings.HasPrefix(texts[j], texts[i]) {
                panic(fmt.Sprintf("context registry: %q is a prefix of %q",
                    texts[i], texts[j]))
            }
        }
    }
}

func lookup(text string) Label {
    for _, l := range Registry {
        if l.Text == text {
            return l
        }
    }
    // refusing unregistered labels is the point
    panic("unregistered context label: " + text)
}

// Framed builds the bytes to sign/MAC: len(label) ‖ label ‖ for each field: len
// ‖ field. Length prefixes make the encoding unambiguous (no "ab"+"c" vs
// "a"+"bc").
func Framed(label string, fields ...[]byte) []byte {
    lookup(label)
    var b []byte
    b = binary.BigEndian.AppendUint16(b, uint16(len(label)))
    b = append(b, label...)
    for _, f := range fields {
        b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
        b = append(b, f...)
    }
    return b
}

func Digest(label string, fields ...[]byte) []byte {
    h := sha256.Sum256(Framed(label, fields...))
    return h[:]
}
