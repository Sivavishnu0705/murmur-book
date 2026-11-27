// devpki.go
// Dev PKI for the local stack, following Chapter 4's hierarchy: an
// offline-style root (P-384), a Services CA constrained to .murmur.internal for
// mTLS (SPIFFE IDs), and a separate Edge CA for the public-facing dev names
// (*.murmur.test) that stands in for the public WebPKI.
package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "math/big"
    "net/url"
    "time"
)

type ca struct {
    cert *x509.Certificate
    key  crypto.Signer
}

func serial() *big.Int { n, _ := rand.Int(rand.Reader,
    new(big.Int).Lsh(big.NewInt(1), 127)); return n }

func newRoot() ca {
    k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    t := &x509.Certificate{SerialNumber: serial(),
        Subject: pkix.Name{CommonName: "Murmur Dev Root R1"},
        NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1,
        0, 0),
        IsCA: true, BasicConstraintsValid: true,
        KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
    der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
    c, _ := x509.ParseCertificate(der)
    return ca{c, k}
}

func (p ca) intermediate(name string, permittedDNS []string,
    eku []x509.ExtKeyUsage) ca {
    k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    t := &x509.Certificate{SerialNumber: serial(),
        Subject: pkix.Name{CommonName: name},
        NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0,
        6, 0),
        IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0,
        MaxPathLenZero: true,
        KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: eku,
        PermittedDNSDomainsCritical: true, PermittedDNSDomains: permittedDNS,
        PermittedURIDomains: []string{"murmur.internal"}}
    der, _ := x509.CreateCertificate(rand.Reader, t, p.cert, &k.PublicKey,
        p.key)
    c, _ := x509.ParseCertificate(der)
    return ca{c, k}
}

// leaf issues a 30-day service certificate (Ch 4: short-lived, renewed
// automatically).
func (p ca) leaf(dns string, spiffe string,
    eku ...x509.ExtKeyUsage) tls.Certificate {
    k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    t := &x509.Certificate{SerialNumber: serial(),
        Subject: pkix.Name{CommonName: dns},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(30 * 24 * time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
        DNSNames: []string{dns}}
    if spiffe != "" {
        u, _ := url.Parse(spiffe)
        t.URIs = []*url.URL{u}
    }
    der, _ := x509.CreateCertificate(rand.Reader, t, p.cert, &k.PublicKey,
        p.key)
    return tls.Certificate{Certificate: [][]byte{der, p.cert.Raw},
        PrivateKey: k}
}

// spkiPin: base64 SHA-256 of the SubjectPublicKeyInfo (Ch 8).
func spkiPin(c *x509.Certificate) string {
    h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
    return base64.StdEncoding.EncodeToString(h[:])
}
