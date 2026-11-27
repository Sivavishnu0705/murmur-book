// Listing 8.7 — Go: lab driver. Builds three CAs, serves each rotation
// scenario, and connects with the pinned client (and the naive one) to show
// which scenarios survive.
package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "math/big"
    "net"
    "strings"
    "time"
)

const host = "api.murmur.example"

type ca struct {
    cert *x509.Certificate
    key  crypto.Signer
}

func issue(name string, parent *ca, isCA bool, dns []string) *ca {
    k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
    t := &x509.Certificate{
        SerialNumber: serial, Subject: pkix.Name{CommonName: name},
        NotBefore: time.Now().Add(-time.Hour),
            NotAfter: time.Now().Add(90 * 24 * time.Hour),
        BasicConstraintsValid: true, IsCA: isCA, DNSNames: dns,
    }
    if isCA {
        t.KeyUsage = x509.KeyUsageCertSign
    } else {
        t.KeyUsage = x509.KeyUsageDigitalSignature
        t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
    }
    signer, signerCert := crypto.Signer(k), t
    if parent != nil {
        signer, signerCert = parent.key, parent.cert
    }
    der, err := x509.CreateCertificate(rand.Reader, t, signerCert, k.Public(),
        signer)
    if err != nil {
        panic(err)
    }
    c, _ := x509.ParseCertificate(der)
    return &ca{c, k}
}

func serve(leaf *ca, chain ...*ca) string {
    certs := [][]byte{leaf.cert.Raw}
    for _, c := range chain {
        certs = append(certs, c.cert.Raw)
    }
    ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
        Certificates: []tls.Certificate{{Certificate: certs,
        PrivateKey: leaf.key}}})
    go func() {
        for {
            c, err := ln.Accept()
            if err != nil {
                return
            }
            c.(*tls.Conn).Handshake()
            c.Close()
        }
    }()
    return ln.Addr().String()
}

func try(cfg *tls.Config, addr string) string {
    c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp",
        addr, cfg)
    if err != nil {
        return "FAIL  " + strings.TrimPrefix(err.Error(), "tls: ")
    }
    c.Close()
    return "OK"
}

func main() {
    // Two public CAs Murmur trusts via the system store, plus a rogue/coerced
    // CA that is ALSO in the trust store (or user/MDM-installed) but must not
    // be accepted.
    rootA := issue("CA-A Root", nil, true, nil)
    // current issuer → pinned
    interA1 := issue("CA-A Issuing 1", rootA, true, nil)
    // CA's next issuer → pinned (backup)
    interA2 := issue("CA-A Issuing 2", rootA, true, nil)
    // surprise new issuer → NOT pinned
    interA3 := issue("CA-A Issuing 3", rootA, true, nil)
    // backup CA → root pinned
    rootB := issue("CA-B Root", nil, true, nil)
    interB1 := issue("CA-B Issuing 1", rootB, true, nil)
    rogue := issue("Rogue Root (trusted by device)", nil, true, nil)

    roots := x509.NewCertPool()
    for _, r := range []*ca{rootA, rootB, rogue} {
        roots.AddCert(r.cert)
    }
    var reports []PinFailure
    pins := &PinSet{
        Pins: map[string]bool{
            SPKIPin(interA1.cert): true,
            SPKIPin(interA2.cert): true,
            SPKIPin(rootB.cert):   true,
        },
        Expires: time.Now().Add(180 * 24 * time.Hour),
        Report:  func(f PinFailure) { reports = append(reports, f) },
    }
    fmt.Println("pins:")
    for _, c := range []*ca{interA1, interA2, rootB} {
        fmt.Printf("  %s  %s\n", SPKIPin(c.cert), c.cert.Subject.CommonName)
    }

    type scenario struct {
        name string
        addr string
    }
    scenarios := []scenario{
        {"1 leaf v1 from CA-A Issuing 1", serve(issue(host, interA1, false,
            []string{host}), interA1)},
        {"2 ROTATE leaf key (same issuer)", serve(issue(host, interA1, false,
            []string{host}), interA1)},
        {"3 CA moves to Issuing 2 (backup pin)", serve(issue(host, interA2,
            false, []string{host}), interA2)},
        {"4 emergency switch to CA-B", serve(issue(host, interB1, false,
            []string{host}), interB1)},
        {"5 CA moves to Issuing 3 (unpinned)", serve(issue(host, interA3, false,
            []string{host}), interA3)},
        {"6 rogue CA MITM", serve(issue(host, rogue, false, []string{host}))},
        {"7 rogue MITM + appended real Issuing 1", serve(issue(host, rogue,
            false, []string{host}), interA1)},
    }
    fmt.Printf("\n%-42s | %-48s | %s\n", "scenario",
        "pinned client (validated chain)", "naive client (presented certs)")
    fmt.Println(strings.Repeat("-", 42) + "-+-" + strings.Repeat("-",
        48) + "-+-" + strings.Repeat("-", 30))
    for _, s := range scenarios {
        fmt.Printf("%-42s | %-48s | %s\n", s.name,
            try(ClientConfig(roots, host, pins), s.addr),
            try(NaiveClientConfig(roots, host, pins), s.addr))
    }

    // Pin set past its expiry: scenario 5 connects again (fail open), by
    // design.
    pins.Expires = time.Now().Add(-time.Hour)
    fmt.Printf("\n%-42s | %s\n", "5 again, after pin-set EXPIRY",
        try(ClientConfig(roots, host, pins), scenarios[4].addr))

    fmt.Printf("\npin-failure reports collected: %d\n", len(reports))
    for _, r := range reports {
        fmt.Printf("  host=%s chain=%v\n", r.Host, abbreviate(r.Presented))
    }
}

func abbreviate(pins []string) []string {
    out := make([]string, len(pins))
    for i, p := range pins {
        out[i] = p[:10] + "…"
    }
    return out
}
