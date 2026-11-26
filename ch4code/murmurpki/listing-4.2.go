// Listing 4.2 — Murmur's private PKI: offline root → intermediates → leaves.
//
//     go run . issue  -out ./pki                       # build the hierarchy
//     go run . issue  -out ./pki-bad -break-intermediate   # lab: CA:FALSE intermediate
//     go run . verify -pki ./pki -leaf murmur-api -dns murmur-api.murmur.internal
package main

import (
       "crypto"
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/x509"
       "crypto/x509/pkix"
       "encoding/pem"
       "flag"
       "fmt"
       "math/big"
       "net/url"
       "os"
       "path/filepath"
       "time"
)

type issued struct {
       cert *x509.Certificate
       key  crypto.Signer
}

// randomSerial returns a positive 127-bit serial (RFC 5280: ≤ 20 octets, positive, unique).
func randomSerial() *big.Int {
       limit := new(big.Int).Lsh(big.NewInt(1), 127)
       n, err := rand.Int(rand.Reader, limit)
       must(err)
       return n.Add(n, big.NewInt(1))
}

func newKey(curve elliptic.Curve) *ecdsa.PrivateKey {
       k, err := ecdsa.GenerateKey(curve, rand.Reader)
       must(err)
       return k
}

// sign creates tmpl signed by parent (or self-signed when parent == nil).
func sign(tmpl *x509.Certificate, key crypto.Signer, parent *issued) *issued {
       tmpl.SerialNumber = randomSerial()
       signerCert, signerKey := tmpl, key
       if parent != nil {
              signerCert, signerKey = parent.cert, parent.key
       }
       der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
       must(err)
       cert, err := x509.ParseCertificate(der)
       must(err)
       return &issued{cert, key}
}

func rootCA(now time.Time) *issued {
       return sign(&x509.Certificate{
              Subject:               pkix.Name{Organization: []string{"Murmur"}, CommonName: "Murmur Root CA R1"},
              NotBefore:             now.Add(-5 * time.Minute), // tolerate small clock skew
              NotAfter:              now.AddDate(10, 0, 0),
              KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
              BasicConstraintsValid: true,
              IsCA:                  true,
              MaxPathLen:            1, // root → intermediate → leaf, no deeper
       }, newKey(elliptic.P384()), nil)
}

// serviceIntermediate may issue only server/client certs for *.murmur.internal.
func serviceIntermediate(root *issued, now time.Time, broken bool) *issued {
       tmpl := &x509.Certificate{
              Subject:                     pkix.Name{Organization: []string{"Murmur"}, CommonName: "Murmur Services CA S1"},
              NotBefore:                   now.Add(-5 * time.Minute),
              NotAfter:                    now.AddDate(3, 0, 0),
              KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
              ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
              BasicConstraintsValid:       true,
              IsCA:                        true,
              MaxPathLen:                  0,
              MaxPathLenZero:              true, // may sign leaves only
              PermittedDNSDomainsCritical: true,
              PermittedDNSDomains:         []string{".murmur.internal"},
              PermittedURIDomains:         []string{"murmur.internal"},
       }
       if broken { // lab: the classic mistake — an "intermediate" issued with CA:FALSE
              tmpl.IsCA, tmpl.MaxPathLen, tmpl.MaxPathLenZero = false, -1, false
       }
       return sign(tmpl, newKey(elliptic.P256()), root)
}

// deviceIntermediate issues short-lived client certificates to enrolled phones (Chapter 9).
func deviceIntermediate(root *issued, now time.Time) *issued {
       return sign(&x509.Certificate{
              Subject:               pkix.Name{Organization: []string{"Murmur"}, CommonName: "Murmur Devices CA D1"},
              NotBefore:             now.Add(-5 * time.Minute),
              NotAfter:              now.AddDate(3, 0, 0),
              KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
              ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
              BasicConstraintsValid: true,
              IsCA:                  true,
              MaxPathLen:            0,
              MaxPathLenZero:        true,
       }, newKey(elliptic.P256()), root)
}

func serverLeaf(ca *issued, service string, now time.Time) *issued {
       id, _ := url.Parse("spiffe://murmur.internal/service/" + service)
       return sign(&x509.Certificate{
              Subject:               pkix.Name{CommonName: service}, // informational only
              NotBefore:             now.Add(-5 * time.Minute),
              NotAfter:              now.Add(30 * 24 * time.Hour), // short-lived; renewed automatically
              KeyUsage:              x509.KeyUsageDigitalSignature,
              ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
              BasicConstraintsValid: true,
              IsCA:                  false,
              DNSNames:              []string{service + ".murmur.internal"}, // SAN: what clients check
              URIs:                  []*url.URL{id},                         // SAN: service identity for mTLS
       }, newKey(elliptic.P256()), ca)
}

func deviceLeaf(ca *issued, deviceID string, now time.Time) *issued {
       id, _ := url.Parse("spiffe://murmur.internal/device/" + deviceID)
       return sign(&x509.Certificate{
              Subject:               pkix.Name{CommonName: deviceID},
              NotBefore:             now.Add(-5 * time.Minute),
              NotAfter:              now.Add(7 * 24 * time.Hour),
              KeyUsage:              x509.KeyUsageDigitalSignature,
              ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
              BasicConstraintsValid: true,
              IsCA:                  false,
              URIs:                  []*url.URL{id},
       }, newKey(elliptic.P256()), ca)
}

func write(dir, name string, it *issued) {
       must(os.MkdirAll(dir, 0o700))
       certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: it.cert.Raw})
       must(os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644))
       keyDER, err := x509.MarshalPKCS8PrivateKey(it.key)
       must(err)
       keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
       must(os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600)) // lab only: real CA keys live in an HSM/KMS
}

func issue(out string, broken bool) {
       now := time.Now()
       root := rootCA(now)
       svc := serviceIntermediate(root, now, broken)
       dev := deviceIntermediate(root, now)
       write(out, "root", root)
       write(out, "services-ca", svc)
       write(out, "devices-ca", dev)
       write(out, "murmur-api", serverLeaf(svc, "murmur-api", now))
       write(out, "murmur-relay", serverLeaf(svc, "murmur-relay", now))
       write(out, "device-d7f3a", deviceLeaf(dev, "d7f3a", now))
       fmt.Println("wrote hierarchy to", out)
}

func load(path string) *x509.Certificate {
       b, err := os.ReadFile(path)
       must(err)
       blk, _ := pem.Decode(b)
       c, err := x509.ParseCertificate(blk.Bytes)
       must(err)
       return c
}

// verify ADDS nothing custom: it uses the standard path validation with explicit options.
func verify(dir, leafName, dnsName string, eku x509.ExtKeyUsage) {
       roots, inters := x509.NewCertPool(), x509.NewCertPool()
       roots.AddCert(load(filepath.Join(dir, "root.crt")))
       inters.AddCert(load(filepath.Join(dir, "services-ca.crt")))
       inters.AddCert(load(filepath.Join(dir, "devices-ca.crt")))
       chains, err := load(filepath.Join(dir, leafName+".crt")).Verify(x509.VerifyOptions{
              DNSName:       dnsName, // hostname verification ("" skips it: client certs)
              Roots:         roots,   // ONLY our root — not the system trust store
              Intermediates: inters,
              KeyUsages:     []x509.ExtKeyUsage{eku},
       })
       if err != nil {
              fmt.Println("REJECTED:", err)
              os.Exit(1)
       }
       for _, c := range chains[0] {
              fmt.Println("  ✓", c.Subject.CommonName)
       }
       fmt.Println("VALID")
}

func main() {
       if len(os.Args) < 2 {
              fmt.Println("usage: issue|verify [flags]")
              os.Exit(2)
       }
       fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
       out := fs.String("out", "./pki", "output directory")
       brk := fs.Bool("break-intermediate", false, "issue the services CA with CA:FALSE (lab)")
       dir := fs.String("pki", "./pki", "PKI directory")
       leaf := fs.String("leaf", "murmur-api", "leaf certificate name")
       dns := fs.String("dns", "", "expected DNS name (empty for client certs)")
       client := fs.Bool("client", false, "verify for clientAuth instead of serverAuth")
       must(fs.Parse(os.Args[2:]))
       switch os.Args[1] {
       case "issue":
              issue(*out, *brk)
       case "verify":
              eku := x509.ExtKeyUsageServerAuth
              if *client {
                     eku = x509.ExtKeyUsageClientAuth
              }
              verify(*dir, *leaf, *dns, eku)
       }
}

func must(err error) {
       if err != nil {
              panic(err)
       }
}
