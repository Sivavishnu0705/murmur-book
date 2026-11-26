// Listing 8.6 — Go: SPKI pinning layered on standard validation, with expiry and reporting.
package main

import (
       "crypto/sha256"
       "crypto/tls"
       "crypto/x509"
       "encoding/base64"
       "errors"
       "fmt"
       "time"
)

// PinSet mirrors Android's <pin-set expiration=…>: SPKI SHA-256 pins (base64) plus an
// expiry after which pinning is skipped (fail open) so an un-updated app never bricks.
type PinSet struct {
       Pins    map[string]bool
       Expires time.Time
       Report  func(PinFailure) // send to a reporting endpoint; never block the user on it
}

type PinFailure struct {
       Host      string
       Presented []string // pins of the VALIDATED chain, leaf first
       Time      time.Time
}

func SPKIPin(c *x509.Certificate) string {
       sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
       return base64.StdEncoding.EncodeToString(sum[:])
}

// Check runs AFTER standard verification (VerifyConnection) and inspects the chain the
// verifier BUILT AND VALIDATED — never the raw certificates the server chose to send.
func (p *PinSet) Check(host string, cs tls.ConnectionState, now time.Time) error {
       if now.After(p.Expires) {
              return nil // expired pin set: fall back to normal validation only
       }
       var seen []string
       for _, chain := range cs.VerifiedChains {
              for _, c := range chain {
                     pin := SPKIPin(c)
                     if p.Pins[pin] {
                            return nil // any pinned key anywhere in a validated chain is enough
                     }
                     seen = append(seen, pin)
              }
       }
       if p.Report != nil {
              p.Report(PinFailure{Host: host, Presented: seen, Time: now})
       }
       return errors.New("no pinned key in validated chain")
}

// ClientConfig: system-style validation (here: the lab's trusted roots) + pinning on top.
func ClientConfig(roots *x509.CertPool, host string, pins *PinSet) *tls.Config {
       return &tls.Config{
              RootCAs:    roots,
              ServerName: host,
              MinVersion: tls.VersionTLS13,
              VerifyConnection: func(cs tls.ConnectionState) error {
                     return pins.Check(host, cs, time.Now())
              },
       }
}

// ⚠️ WRONG — FOR ILLUSTRATION ONLY: pins checked against the certificates the SERVER SENT.
// An attacker can append any public certificate (e.g. your real intermediate) to their own
// chain; it is ignored by path validation but satisfies this check.
func NaiveClientConfig(roots *x509.CertPool, host string, pins *PinSet) *tls.Config {
       return &tls.Config{
              RootCAs:    roots,
              ServerName: host,
              MinVersion: tls.VersionTLS13,
              VerifyConnection: func(cs tls.ConnectionState) error {
                     for _, c := range cs.PeerCertificates { // ⚠️ presented, not validated
                            if pins.Pins[SPKIPin(c)] {
                                   return nil
                            }
                     }
                     return fmt.Errorf("no pinned key in presented certs")
              },
       }
}
