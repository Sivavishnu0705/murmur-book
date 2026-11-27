// Listing 9.4a — Go: verifying an Android Key Attestation chain (outline + key
// checks).
package main

import (
    "bytes"
    "crypto/x509"
    "encoding/asn1"
    "errors"
    "fmt"
)

var oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const (
    SecSoftware    = 0
    SecTEE         = 1
    SecStrongBox   = 2
    BootVerified   = 0
    tagRootOfTrust = 704
    tagAppID       = 709
)

type keyDescription struct {
    AttestationVersion       int
    AttestationSecurityLevel asn1.Enumerated
    KeyMintVersion           int
    KeyMintSecurityLevel     asn1.Enumerated
    AttestationChallenge     []byte
    UniqueID                 []byte
    // AuthorizationList: parsed field by field below
    SoftwareEnforced         asn1.RawValue
    HardwareEnforced         asn1.RawValue
}

type rootOfTrust struct {
    VerifiedBootKey   []byte
    DeviceLocked      bool
    VerifiedBootState asn1.Enumerated
    VerifiedBootHash  []byte `asn1:"optional"`
}

type packageInfo struct {
    Name    []byte
    Version int64
}

type attestationAppID struct {
    Packages         []packageInfo `asn1:"set"`
    SignatureDigests [][]byte      `asn1:"set"`
}

// AndroidPolicy: what Murmur requires before issuing a device certificate.
type AndroidPolicy struct {
    // Google attestation roots: BOTH the RSA and the 2026 ECDSA P-384 root
    Roots             *x509.CertPool
    PackageName       string
    SigningCertSHA256 []byte // SHA-256 of Murmur's app signing certificate
    MinSecurityLevel  int    // SecTEE, or SecStrongBox for higher assurance
}

type AndroidAttestation struct {
    SecurityLevel int
    DeviceLocked  bool
    BootVerified  bool
}

// VerifyAndroid checks an attestation chain (leaf first) produced for a key
// generated with setAttestationChallenge(challenge), and returns the attested
// leaf key's certificate.
func VerifyAndroid(chain []*x509.Certificate, challenge []byte,
    p AndroidPolicy) (*x509.Certificate, *AndroidAttestation, error) {
    if len(chain) < 2 {
        return nil, nil, errors.New("attestation chain too short")
    }
    // 1. Chain must verify to a Google attestation root. (Attestation certs are
    // not TLS certs: no hostname, and their EKU/usage don't follow the Web PKI
    // profile.)
    inter := x509.NewCertPool()
    for _, c := range chain[1:] {
        inter.AddCert(c)
    }
    if _, err := chain[0].Verify(x509.VerifyOptions{Roots: p.Roots,
        Intermediates: inter,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
        return nil, nil, fmt.Errorf("attestation chain: %w", err)
    }
    // 2. (Production) check every chain certificate's serial against Google's
    // attestation revocation status list, and that no certificate is expired.

    // 3. Find the key description extension in the leaf (the attested key's
    // certificate).
    var raw []byte
    for _, e := range chain[0].Extensions {
        if e.Id.Equal(oidKeyDescription) {
            raw = e.Value
        }
    }
    if raw == nil {
        return nil, nil, errors.New("no key attestation extension")
    }
    var kd keyDescription
    if _, err := asn1.Unmarshal(raw, &kd); err != nil {
        return nil, nil, fmt.Errorf("key description: %w", err)
    }
    // 4. Freshness: the challenge is the server's single-use nonce.
    if !bytes.Equal(kd.AttestationChallenge, challenge) {
        return nil, nil, errors.New("attestation challenge mismatch (replay?)")
    }
    // 5. Where the key lives: both the attestation and the key itself in
    // hardware.
    if int(kd.AttestationSecurityLevel) < p.MinSecurityLevel || int(
        kd.KeyMintSecurityLevel) < p.MinSecurityLevel {
        return nil, nil, fmt.Errorf("security level %d/%d below required %d",
            kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel,
            p.MinSecurityLevel)
    }
    // 6. Device state: root of trust from the HARDWARE-enforced list only.
    hw := authList(kd.HardwareEnforced.Bytes)
    rotRaw, ok := hw[tagRootOfTrust]
    if !ok {
        return nil, nil, errors.New("no hardware-enforced root of trust")
    }
    var rot rootOfTrust
    if _, err := asn1.Unmarshal(rotRaw, &rot); err != nil {
        return nil, nil, fmt.Errorf("root of trust: %w", err)
    }
    // 7. Which app asked for the key: package name and signing certificate
    // digest.
    sw := authList(kd.SoftwareEnforced.Bytes)
    appRaw, ok := sw[tagAppID]
    if !ok {
        return nil, nil, errors.New("no attestation application id")
    }
    var appOctets []byte
    if _, err := asn1.Unmarshal(appRaw, &appOctets); err != nil {
        return nil, nil, err
    }
    var app attestationAppID
    if _, err := asn1.Unmarshal(appOctets, &app); err != nil {
        return nil, nil, fmt.Errorf("application id: %w", err)
    }
    if !hasPackage(app, p.PackageName) || !hasDigest(app, p.SigningCertSHA256) {
        return nil, nil,
            errors.New("key was not created by the genuine Murmur app")
    }
    return chain[0], &AndroidAttestation{
        SecurityLevel: int(kd.KeyMintSecurityLevel),
        DeviceLocked:  rot.DeviceLocked,
        BootVerified:  int(rot.VerifiedBootState) == BootVerified,
    }, nil
}

// authList splits an AuthorizationList (SEQUENCE of [tag] EXPLICIT values) by
// tag number. Unknown tags are kept but ignored, so new KeyMint fields don't
// break parsing.
func authList(b []byte) map[int][]byte {
    out := map[int][]byte{}
    for len(b) > 0 {
        var rv asn1.RawValue
        rest, err := asn1.Unmarshal(b, &rv)
        if err != nil {
            break
        }
        if rv.Class == asn1.ClassContextSpecific {
            out[rv.Tag] = rv.Bytes // the explicitly tagged inner element
        }
        b = rest
    }
    return out
}

func hasPackage(a attestationAppID, name string) bool {
    for _, p := range a.Packages {
        if string(p.Name) == name {
            return true
        }
    }
    return false
}

func hasDigest(a attestationAppID, d []byte) bool {
    for _, x := range a.SignatureDigests {
        if bytes.Equal(x, d) {
            return true
        }
    }
    return false
}
