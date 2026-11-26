// Listing 9.6 — Go: lab driver. Simulates Android Key Attestation and App Attest with lab
// roots (real devices chain to Google's and Apple's roots), enrolls devices, and calls the
// mTLS endpoint in each scenario.
package main

import (
       "context"
       "crypto"
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/sha256"
       "crypto/tls"
       "crypto/x509"
       "crypto/x509/pkix"
       "encoding/asn1"
       "encoding/binary"
       "fmt"
       "io"
       "log"
       "math/big"
       "net"
       "net/http"
       "net/url"
       "strings"
       "sync"
       "time"
)

type kp struct {
       cert *x509.Certificate
       key  *ecdsa.PrivateKey
}

func newKey() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }

func mk(t *x509.Certificate, pub crypto.PublicKey, parent *kp, self *ecdsa.PrivateKey) *x509.Certificate {
       t.SerialNumber, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
       t.NotBefore, t.BasicConstraintsValid = time.Now().Add(-time.Hour), true
       if t.NotAfter.IsZero() {
              t.NotAfter = time.Now().Add(365 * 24 * time.Hour)
       }
       signer, sc := crypto.Signer(self), t
       if parent != nil {
              signer, sc = parent.key, parent.cert
       }
       der, err := x509.CreateCertificate(rand.Reader, t, sc, pub, signer)
       if err != nil {
              panic(err)
       }
       c, _ := x509.ParseCertificate(der)
       return c
}

func ca(name string, parent *kp) *kp {
       k := newKey()
       return &kp{mk(&x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true,
              KeyUsage: x509.KeyUsageCertSign}, &k.PublicKey, parent, k), k}
}

// ---------- simulated Android Keystore: key + attestation chain ----------
type androidOpts struct {
       pkg       string
       secLevel  int
       bootState int
}

func explicit(tag int, inner []byte) []byte {
       b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
       return b
}

func androidAttest(root, inter *kp, key *ecdsa.PrivateKey, challenge []byte, o androidOpts, sigDigest []byte) []*x509.Certificate {
       rot, _ := asn1.Marshal(rootOfTrust{VerifiedBootKey: make([]byte, 32), DeviceLocked: true,
              VerifiedBootState: asn1.Enumerated(o.bootState), VerifiedBootHash: make([]byte, 32)})
       app, _ := asn1.Marshal(attestationAppID{Packages: []packageInfo{{Name: []byte(o.pkg), Version: 42}},
              SignatureDigests: [][]byte{sigDigest}})
       appOctets, _ := asn1.Marshal(app)
       seq := func(b []byte) asn1.RawValue {
              return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 16, IsCompound: true, Bytes: b}
       }
       kd, _ := asn1.Marshal(keyDescription{
              AttestationVersion: 300, AttestationSecurityLevel: asn1.Enumerated(o.secLevel),
              KeyMintVersion: 300, KeyMintSecurityLevel: asn1.Enumerated(o.secLevel),
              AttestationChallenge: challenge, UniqueID: []byte{},
              SoftwareEnforced: seq(explicit(tagAppID, appOctets)),
              HardwareEnforced: seq(explicit(tagRootOfTrust, rot)),
       })
       leaf := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"},
              ExtraExtensions: []pkix.Extension{{Id: oidKeyDescription, Value: kd}}}, &key.PublicKey, inter, nil)
       return []*x509.Certificate{leaf, inter.cert, root.cert}
}

// ---------- simulated App Attest ----------
func cborHead(major byte, n int) []byte {
       switch {
       case n < 24:
              return []byte{major<<5 | byte(n)}
       case n < 256:
              return []byte{major<<5 | 24, byte(n)}
       default:
              return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
       }
}
func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cborText(s string) []byte  { return append(cborHead(3, len(s)), s...) }

func appAttest(root, inter *kp, appID string, clientDataHash []byte) (obj, keyID []byte) {
       k := newKey()
       pt, _ := k.PublicKey.ECDH()
       kid := sha256.Sum256(pt.Bytes())
       rp := sha256.Sum256([]byte(appID))
       auth := append(rp[:], 0x40)                        // flags: attested credential data
       auth = binary.BigEndian.AppendUint32(auth, 0)      // signCount
       auth = append(auth, []byte("appattestdevelop")...) // aaguid (development)
       auth = binary.BigEndian.AppendUint16(auth, 32)     // credentialId length
       auth = append(auth, kid[:]...)                     // credentialId = keyId
       nonce := sha256.Sum256(append(append([]byte{}, auth...), clientDataHash...))
       ext, _ := asn1.Marshal(struct {
              Nonce []byte `asn1:"explicit,tag:1"`
       }{nonce[:]})
       leaf := mk(&x509.Certificate{Subject: pkix.Name{CommonName: hex32(kid[:])},
              ExtraExtensions: []pkix.Extension{{Id: oidAppAttestNonce, Value: ext}}}, &k.PublicKey, inter, nil)
       obj = append(cborHead(5, 3), cborText("fmt")...)
       obj = append(obj, cborText("apple-appattest")...)
       obj = append(obj, cborText("attStmt")...)
       obj = append(obj, cborHead(5, 2)...)
       obj = append(obj, cborText("x5c")...)
       obj = append(obj, cborHead(4, 2)...)
       obj = append(obj, cborBytes(leaf.Raw)...)
       obj = append(obj, cborBytes(inter.cert.Raw)...)
       obj = append(obj, cborText("receipt")...)
       obj = append(obj, cborBytes([]byte("lab-receipt"))...)
       obj = append(obj, cborText("authData")...)
       obj = append(obj, cborBytes(auth)...)
       return obj, kid[:]
}

func hex32(b []byte) string { return fmt.Sprintf("%x", b[:8]) }

func pop(key *ecdsa.PrivateKey, nonce []byte, acct string) []byte {
       s, _ := ecdsa.SignASN1(rand.Reader, key, popMessage(nonce, acct))
       return s
}

func main() {
       // Murmur private PKI (Chapter 4 shape)
       root := ca("Murmur Root CA R1", nil)
       services := ca("Murmur Services CA S1", root)
       devices := ca("Murmur Devices CA D1", root)
       srvKey := newKey()
       srvCert := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "enroll"}, DNSNames: []string{"enroll.murmur.example"},
              ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature},
              &srvKey.PublicKey, services, nil)

       // Lab attestation roots (stand-ins for Google's and Apple's)
       gRoot := ca("LAB Hardware Attestation Root (simulates Google)", nil)
       gInter := ca("LAB Attestation Intermediate", gRoot)
       aRoot := ca("LAB App Attestation Root CA (simulates Apple)", nil)
       aInter := ca("LAB App Attestation CA 1", aRoot)
       gPool, aPool := x509.NewCertPool(), x509.NewCertPool()
       gPool.AddCert(gRoot.cert)
       aPool.AddCert(aRoot.cert)
       murmurSig := sha256.Sum256([]byte("murmur release signing certificate"))
       const appID = "ABCDE12345.example.murmur"

       reg := NewRegistry()
       en := &Enroller{Nonces: NewNonceStore(), Registry: reg, DevicesCA: devices.cert, CAKey: devices.key,
              Android: AndroidPolicy{Roots: gPool, PackageName: "example.murmur", SigningCertSHA256: murmurSig[:], MinSecurityLevel: SecTEE},
              Apple:   ApplePolicy{Root: aPool, AppID: appID}}

       // mTLS server
       mux := http.NewServeMux()
       mux.Handle("/v1/devices/", WithDevice(devices.cert, http.HandlerFunc(KeysHandler)))
       ln, _ := tls.Listen("tcp", "127.0.0.1:0",
              MTLSConfig(tls.Certificate{Certificate: [][]byte{srvCert.Raw, services.cert.Raw}, PrivateKey: srvKey},
                     root.cert, devices.cert, reg))
       srvLog := &lastLine{}
       go (&http.Server{Handler: mux, ErrorLog: log.New(srvLog, "", 0)}).Serve(ln)

       call := func(clientCert *tls.Certificate, path string) string {
              roots := x509.NewCertPool()
              roots.AddCert(root.cert)
              cfg := &tls.Config{RootCAs: roots, ServerName: "enroll.murmur.example", MinVersion: tls.VersionTLS13}
              if clientCert != nil {
                     cfg.Certificates = []tls.Certificate{*clientCert}
              }
              tr := &http.Transport{TLSClientConfig: cfg, DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
                     return net.Dial("tcp", ln.Addr().String())
              }}
              resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://enroll.murmur.example" + path)
              if err != nil {
                     msg := err.Error()
                     if i := strings.LastIndex(msg, ": "); i >= 0 {
                            msg = msg[i+2:]
                     }
                     time.Sleep(20 * time.Millisecond) // let the server log its reason
                     return "REJECTED in handshake — server: " + srvLog.reason()
              }
              defer resp.Body.Close()
              b, _ := io.ReadAll(resp.Body)
              return fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(b)))
       }
       asTLS := func(c *x509.Certificate, k *ecdsa.PrivateKey) *tls.Certificate {
              return &tls.Certificate{Certificate: [][]byte{c.Raw, devices.cert.Raw}, PrivateKey: k}
       }
       row := func(n, desc, result string) { fmt.Printf("%-3s %-52s %s\n", n, desc, result) }
       enrollAndroid := func(o androidOpts, key *ecdsa.PrivateKey, nonce []byte) (*x509.Certificate, string, error) {
              chain := androidAttest(gRoot, gInter, key, nonce, o, murmurSig[:])
              return en.Enroll(EnrollRequest{AccountID: "alice", Nonce: nonce, DeviceKey: &key.PublicKey,
                     PoP: pop(key, nonce, "alice"), AndroidChain: chain})
       }
       genuine := androidOpts{pkg: "example.murmur", secLevel: SecStrongBox, bootState: BootVerified}

       // 1. Genuine Android device enrolls and calls its own endpoint
       aKey := newKey()
       n1 := en.Nonces.Issue()
       aCert, aID, err := enrollAndroid(genuine, aKey, n1)
       row("1", "Android (StrongBox, verified boot) enrolls", fmt.Sprintf("issued device %s, valid %v", aID, aCert.NotAfter.Sub(aCert.NotBefore).Round(time.Hour)))
       if err != nil {
              panic(err)
       }
       row("", "  → GET own keys over mTLS", call(asTLS(aCert, aKey), "/v1/devices/"+aID+"/keys"))
       row("2", "same request with NO client certificate", call(nil, "/v1/devices/"+aID+"/keys"))
       // 3. Second device; A tries to act on B
       bKey := newKey()
       bCert, bID, _ := enrollAndroid(genuine, bKey, en.Nonces.Issue())
       row("3", "device A requests device B's keys", call(asTLS(aCert, aKey), "/v1/devices/"+bID+"/keys"))
       // 3b. Certificates are public: attacker presents B's certificate, signing with its own key
       row("3b", "B's certificate presented without B's private key", call(asTLS(bCert, newKey()), "/v1/devices/"+bID+"/keys"))
       // 4. Replay A's enrollment (nonce already consumed)
       _, _, err = enrollAndroid(genuine, aKey, n1)
       row("4", "replay of A's attestation (same nonce)", "REJECTED: "+err.Error())
       // 5. Repackaged app
       _, _, err = enrollAndroid(androidOpts{pkg: "example.murmur.mod", secLevel: SecTEE, bootState: BootVerified}, newKey(), en.Nonces.Issue())
       row("5", "repackaged app (different package/signer)", "REJECTED: "+err.Error())
       // 6. Software-backed key (emulator / no secure hardware)
       _, _, err = enrollAndroid(androidOpts{pkg: "example.murmur", secLevel: SecSoftware, bootState: BootVerified}, newKey(), en.Nonces.Issue())
       row("6", "software-only key (emulator)", "REJECTED: "+err.Error())
       // 7. Unlocked bootloader / unverified boot
       _, _, err = enrollAndroid(androidOpts{pkg: "example.murmur", secLevel: SecTEE, bootState: 2}, newKey(), en.Nonces.Issue())
       row("7", "unverified boot state (unlocked bootloader)", "REJECTED: "+err.Error())
       // 8. Attestation for a different key than the one to certify
       k1, k2 := newKey(), newKey()
       n8 := en.Nonces.Issue()
       _, _, err8 := en.Enroll(EnrollRequest{AccountID: "alice", Nonce: n8, DeviceKey: &k2.PublicKey, PoP: pop(k2, n8, "alice"),
              AndroidChain: androidAttest(gRoot, gInter, k1, n8, genuine, murmurSig[:])})
       row("8", "attests key K1, asks to certify key K2", "REJECTED: "+errString(err8))

       // 9. iOS genuine: Secure Enclave mTLS key + App Attest over (nonce || SPKI)
       iKey := newKey()
       n9 := en.Nonces.Issue()
       spki, _ := x509.MarshalPKIXPublicKey(&iKey.PublicKey)
       cdh := sha256.Sum256(append(append([]byte{}, n9...), spki...))
       obj, kid := appAttest(aRoot, aInter, appID, cdh[:])
       iCert, iID, err := en.Enroll(EnrollRequest{AccountID: "bob", Nonce: n9, DeviceKey: &iKey.PublicKey,
              PoP: pop(iKey, n9, "bob"), AppAttestObject: obj, AppAttestKeyID: kid})
       if err != nil {
              panic(err)
       }
       row("9", "iOS (App Attest binds nonce + mTLS key) enrolls", "issued device "+iID)
       row("", "  → GET own keys over mTLS", call(asTLS(iCert, iKey), "/v1/devices/"+iID+"/keys"))
       // 10. iOS: attacker reuses a genuine attestation but swaps in their own key
       n10 := en.Nonces.Issue()
       victimSPKI, _ := x509.MarshalPKIXPublicKey(&newKey().PublicKey)
       cdh10 := sha256.Sum256(append(append([]byte{}, n10...), victimSPKI...))
       obj10, kid10 := appAttest(aRoot, aInter, appID, cdh10[:])
       evil := newKey()
       _, _, err = en.Enroll(EnrollRequest{AccountID: "bob", Nonce: n10, DeviceKey: &evil.PublicKey,
              PoP: pop(evil, n10, "bob"), AppAttestObject: obj10, AppAttestKeyID: kid10})
       row("10", "iOS attestation for key X, attacker submits key Y", "REJECTED: "+errString(err))
       // 11. A service certificate (also clientAuth) on the device endpoint
       sKey := newKey()
       sURI, _ := url.Parse("spiffe://murmur.internal/service/murmur-relay")
       sCert := mk(&x509.Certificate{Subject: pkix.Name{CommonName: "murmur-relay"}, URIs: []*url.URL{sURI},
              ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature},
              &sKey.PublicKey, services, nil)
       row("11", "service certificate used as a device", call(&tls.Certificate{Certificate: [][]byte{sCert.Raw, services.cert.Raw}, PrivateKey: sKey}, "/v1/devices/"+aID+"/keys"))
       // 12. Revoked device
       reg.Revoke(aID)
       row("12", "device A after remote revocation", call(asTLS(aCert, aKey), "/v1/devices/"+aID+"/keys"))
}

func errString(e error) string {
       if e == nil {
              return "(accepted!)"
       }
       return e.Error()
}

// lastLine keeps the server's most recent error log line (the handshake rejection reason).
type lastLine struct {
       mu   sync.Mutex
       line string
}

func (l *lastLine) Write(p []byte) (int, error) {
       l.mu.Lock()
       l.line = strings.TrimSpace(string(p))
       l.mu.Unlock()
       return len(p), nil
}

func (l *lastLine) reason() string {
       l.mu.Lock()
       defer l.mu.Unlock()
       if i := strings.LastIndex(l.line, ": "); i >= 0 {
              return l.line[i+2:]
       }
       return l.line
}
