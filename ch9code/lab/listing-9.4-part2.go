// Listing 9.4b — Go: verifying an App Attest attestation object (key checks).
package main

import (
       "bytes"
       "crypto/ecdsa"
       "crypto/sha256"
       "crypto/x509"
       "encoding/asn1"
       "encoding/binary"
       "errors"
       "fmt"
)

var oidAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

type ApplePolicy struct {
       Root       *x509.CertPool // Apple App Attestation Root CA
       AppID      string         // "<TeamID>.<BundleID>"
       Production bool
}

// VerifyAppAttest checks the CBOR attestation object from DCAppAttestService.attestKey.
// clientDataHash is what the app passed in: Murmur uses SHA-256(nonce || mTLS key SPKI).
func VerifyAppAttest(obj []byte, keyID []byte, clientDataHash []byte, p ApplePolicy) (*ecdsa.PublicKey, error) {
       top, err := cborMap(obj)
       if err != nil {
              return nil, err
       }
       if string(top["fmt"].([]byte)) != "apple-appattest" {
              return nil, errors.New("wrong attestation format")
       }
       stmt := top["attStmt"].(map[string]any)
       x5c := stmt["x5c"].([]any)
       authData := top["authData"].([]byte)

       // 1. Certificate chain to Apple's App Attestation Root CA.
       certs := make([]*x509.Certificate, len(x5c))
       for i, c := range x5c {
              if certs[i], err = x509.ParseCertificate(c.([]byte)); err != nil {
                     return nil, err
              }
       }
       inter := x509.NewCertPool()
       for _, c := range certs[1:] {
              inter.AddCert(c)
       }
       if _, err := certs[0].Verify(x509.VerifyOptions{Roots: p.Root, Intermediates: inter,
              KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
              return nil, fmt.Errorf("app attest chain: %w", err)
       }
       // 2–3. nonce = SHA-256(authData || clientDataHash) must equal the leaf's extension.
       want := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
       var got []byte
       for _, e := range certs[0].Extensions {
              if e.Id.Equal(oidAppAttestNonce) {
                     var seq struct {
                            Nonce []byte `asn1:"explicit,tag:1"`
                     }
                     if _, err := asn1.Unmarshal(e.Value, &seq); err != nil {
                            return nil, err
                     }
                     got = seq.Nonce
              }
       }
       if !bytes.Equal(got, want[:]) {
              return nil, errors.New("nonce mismatch: attestation not bound to this challenge")
       }
       // 4. keyId = SHA-256 of the leaf's public key (uncompressed point).
       pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
       if !ok {
              return nil, errors.New("unexpected key type")
       }
       ecdhPub, err := pub.ECDH()
       if err != nil {
              return nil, err
       }
       kid := sha256.Sum256(ecdhPub.Bytes()) // uncompressed point: 0x04 || X || Y
       if !bytes.Equal(kid[:], keyID) {
              return nil, errors.New("keyId mismatch")
       }
       // 5. authData: rpIdHash | flags | signCount | aaguid | credIdLen | credId | …
       if len(authData) < 37+16+2+32 {
              return nil, errors.New("authData too short")
       }
       rp := sha256.Sum256([]byte(p.AppID))
       if !bytes.Equal(authData[:32], rp[:]) {
              return nil, errors.New("rpIdHash is not this app")
       }
       if binary.BigEndian.Uint32(authData[33:37]) != 0 {
              return nil, errors.New("counter must be 0 for a new attestation")
       }
       aaguid := authData[37:53]
       wantAAGUID := []byte("appattestdevelop")
       if p.Production {
              wantAAGUID = append([]byte("appattest"), make([]byte, 7)...)
       }
       if !bytes.Equal(aaguid, wantAAGUID) {
              return nil, errors.New("wrong App Attest environment")
       }
       credLen := int(binary.BigEndian.Uint16(authData[53:55]))
       if credLen != 32 || !bytes.Equal(authData[55:55+credLen], keyID) {
              return nil, errors.New("credentialId mismatch")
       }
       return pub, nil // store with counter=0; later assertions must increase the counter
}

// cborMap is a minimal CBOR decoder: enough for App Attest (maps, arrays, byte/text strings,
// small unsigned ints). Production code should use a maintained CBOR library.
func cborMap(b []byte) (map[string]any, error) {
       v, _, err := cborItem(b)
       if err != nil {
              return nil, err
       }
       m, ok := v.(map[string]any)
       if !ok {
              return nil, errors.New("CBOR: top level is not a map")
       }
       return m, nil
}

func cborItem(b []byte) (any, []byte, error) {
       if len(b) == 0 {
              return nil, nil, errors.New("CBOR: truncated")
       }
       major, info := b[0]>>5, b[0]&0x1f
       b = b[1:]
       var n uint64
       switch {
       case info < 24:
              n = uint64(info)
       case info == 24 && len(b) >= 1:
              n, b = uint64(b[0]), b[1:]
       case info == 25 && len(b) >= 2:
              n, b = uint64(binary.BigEndian.Uint16(b)), b[2:]
       case info == 26 && len(b) >= 4:
              n, b = uint64(binary.BigEndian.Uint32(b)), b[4:]
       default:
              return nil, nil, errors.New("CBOR: unsupported length encoding")
       }
       switch major {
       case 0:
              return n, b, nil
       case 2, 3:
              if uint64(len(b)) < n {
                     return nil, nil, errors.New("CBOR: truncated string")
              }
              return b[:n], b[n:], nil
       case 4:
              arr := make([]any, 0, n)
              for i := uint64(0); i < n; i++ {
                     var v any
                     var err error
                     if v, b, err = cborItem(b); err != nil {
                            return nil, nil, err
                     }
                     arr = append(arr, v)
              }
              return arr, b, nil
       case 5:
              m := map[string]any{}
              for i := uint64(0); i < n; i++ {
                     k, rest, err := cborItem(b)
                     if err != nil {
                            return nil, nil, err
                     }
                     v, rest2, err := cborItem(rest)
                     if err != nil {
                            return nil, nil, err
                     }
                     m[string(k.([]byte))] = v
                     b = rest2
              }
              return m, b, nil
       }
       return nil, nil, fmt.Errorf("CBOR: unsupported major type %d", major)
}
