// Listing 5.2 — Go: adding checks on top of standard validation (right) vs.
// replacing it (wrong).
package main

import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "time"
)

// Murmur policy: short-lived certificates only
const maxLeafLifetime = 100 * 24 * time.Hour

// RIGHT: keep Go's full verification (chain, signatures, validity, Basic
// Constraints, EKU, name constraints, hostname) and ADD a policy check
// afterwards. VerifyConnection runs after standard verification, on every
// connection — including resumed ones (VerifyPeerCertificate is skipped on
// resumption).
func correctConfig(roots *x509.CertPool, serverName string) *tls.Config {
    return &tls.Config{
        RootCAs:    roots,      // only the anchors this client should trust
        ServerName: serverName, // the name that hostname verification checks
        MinVersion: tls.VersionTLS13,
        VerifyConnection: func(cs tls.ConnectionState) error {
            if len(cs.VerifiedChains) == 0 {
                // never reached unless misconfigured
                return errors.New("no verified chain")
            }
            leaf := cs.VerifiedChains[0][0]
            if life := leaf.NotAfter.Sub(
                leaf.NotBefore); life > maxLeafLifetime {
                return fmt.Errorf(
                    "policy: leaf valid for %.0f days, limit is %.0f",
                    life.Hours()/24, maxLeafLifetime.Hours()/24)
            }
            return nil
        },
    }
}

// ⚠️ WRONG — FOR ILLUSTRATION ONLY. InsecureSkipVerify turns OFF all standard
// checks; the "replacement" below re-implements just one of them (the
// hostname).
func brokenConfig(roots *x509.CertPool, serverName string) *tls.Config {
    return &tls.Config{
        InsecureSkipVerify: true, // ⚠️ disables chain, expiry, CA, EKU checks
        MinVersion:         tls.VersionTLS13,
        VerifyPeerCertificate: func(rawCerts [][]byte,
            _ [][]*x509.Certificate) error {
            leaf, err := x509.ParseCertificate(rawCerts[0])
            if err != nil {
                return err
            }
            // ⚠️ "valid name" ≠ "valid certificate"
            return leaf.VerifyHostname(serverName)
        },
    }
}
