// main.go
// Listing 24.3 — Go: lab driver — the identity-key upload under attack.
package main

import (
       "bufio"
       "bytes"
       "crypto/ecdh"
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/sha256"
       "crypto/tls"
       "crypto/x509"
       "encoding/json"
       "fmt"
       "io"
       "net/http"
       "net/http/httptest"
       "strconv"
       "strings"
       "time"
)

type device struct {
       account, id string
       dpop        *ecdsa.PrivateKey
       ik          *ecdh.PrivateKey
}

func newDevice(acct, id string) *device {
       d, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       k, _ := ecdh.X25519().GenerateKey(rand.Reader)
       return &device{acct, id, d, k}
}

func (d *device) pub() []byte { return elliptic.Marshal(elliptic.P256(), d.dpop.X, d.dpop.Y) }

// sign builds a complete, signed upload body for the given TLS exporter.
func (d *device) sign(exporter []byte, now time.Time) UploadBody {
       b := UploadBody{Account: d.account, Device: d.id, IdentityKey: d.ik.PublicKey().Bytes(),
              DPoPPub: d.pub(), IssuedAt: now.Unix()}
       st := statement(&b, exporter)
       h := sha256.Sum256(st)
       b.SigDPoP, _ = ecdsa.SignASN1(rand.Reader, d.dpop, h[:])
       s := SignXEdDSA(d.ik.Bytes(), st)
       b.SigIK = s[:]
       return b
}

func dial(srv *httptest.Server) (*tls.Conn, []byte) {
       pool := x509.NewCertPool()
       pool.AddCert(srv.Certificate())
       c, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
       if err != nil {
              panic(err)
       }
       cs := c.ConnectionState()
       exp, _ := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
       return c, exp
}

func post(c *tls.Conn, token string, body UploadBody) string {
       j, _ := json.Marshal(body)
       req, _ := http.NewRequest("POST", "https://murmur/v1/keys/identity", bytes.NewReader(j))
       req.Header.Set("Authorization", token)
       req.Write(c)
       resp, err := http.ReadResponse(bufio.NewReader(c), req)
       if err != nil {
              return err.Error()
       }
       b, _ := io.ReadAll(resp.Body)
       if resp.StatusCode == 204 {
              return "204 accepted"
       }
       text := strings.TrimSpace(string(b))
       if !strings.HasPrefix(text, strconv.Itoa(resp.StatusCode)) {
              return fmt.Sprintf("status %d does not match body %q (!)", resp.StatusCode, text)
       }
       return text
}

func main() {
       now := time.Now()
       alice := newDevice("alice", "alice/2")
       ks := &KeyServer{Keys: map[string][]byte{}, Now: func() time.Time { return now }, Tokens: map[string]Token{
              "tok-alice": {Account: "alice", Device: "alice/2", Jkt: jktOf(alice.pub()), Scopes: []string{"keys:write"}, Acr: "phr", AuthTime: now.Add(-time.Minute)},
              "tok-stale": {Account: "alice", Device: "alice/2", Jkt: jktOf(alice.pub()), Scopes: []string{"keys:write"}, Acr: "phr", AuthTime: now.Add(-3 * time.Hour)},
       }}
       srv := httptest.NewTLSServer(ks)
       defer srv.Close()
       row := func(label, result string) { fmt.Printf("  %-56s %s\n", label, result) }

       fmt.Println("── Identity key upload ──")
       c, exp := dial(srv)
       row("alice/2 uploads over its own TLS connection", post(c, "tok-alice", alice.sign(exp, now)))
       c.Close()

       mallory := newDevice("alice", "alice/2") // has a STOLEN access token, but her own keys
       c, exp = dial(srv)
       row("stolen token + attacker's own keys", post(c, "tok-alice", mallory.sign(exp, now)))
       c.Close()

       // Malware tricks alice/2 into signing a statement for ITS connection, then replays it from
       // the attacker's machine (with the stolen token) over a DIFFERENT connection.
       c1, exp1 := dial(srv)
       captured := alice.sign(exp1, now)
       c1.Close()
       c2, _ := dial(srv)
       row("captured statement relayed over another TLS connection", post(c2, "tok-alice", captured))
       c2.Close()

       c, exp = dial(srv)
       row("old session (passkey auth 3 h ago)", post(c, "tok-stale", alice.sign(exp, now)))
       c.Close()

       other := newDevice("alice", "alice/9")
       other.dpop = alice.dpop // same session key, statement names another device
       c, exp = dial(srv)
       row("statement names a different device than the token", post(c, "tok-alice", other.sign(exp, now)))
       c.Close()

       // Alice's own, fully authorized session tries to claim BOB's identity key as hers (an
       // unknown-key-share at the directory): she can sign with her DPoP key, not with Bob's key.
       c, exp = dial(srv)
       b := alice.sign(exp, now)
       b.IdentityKey = newDevice("bob", "bob/1").ik.PublicKey().Bytes()
       h := sha256.Sum256(statement(&b, exp))
       b.SigDPoP, _ = ecdsa.SignASN1(rand.Reader, alice.dpop, h[:])
       row("own session claims another user's identity key", post(c, "tok-alice", b))
       c.Close()

       fmt.Println("── Cross-protocol signature reuse ──")
       bob := newDevice("bob", "bob/1")
       keys := map[string][]byte{"bob/1": bob.ik.PublicKey().Bytes()}
       spk, _ := ecdh.X25519().GenerateKey(rand.Reader)
       spkSig := SignXEdDSA(bob.ik.Bytes(), append([]byte{0x05}, spk.PublicKey().Bytes()...)) // PUBLIC: in Bob's prekey bundle
       err := NaiveRotate(keys, "bob/1", spk.PublicKey().Bytes(), spkSig)
       row("naive 'rotate identity key' fed Bob's bundle SPK signature", fmt.Sprintf("err=%v → Bob's identity key replaced", err))
       var ik [32]byte
       copy(ik[:], bob.ik.PublicKey().Bytes())
       var sig [64]byte
       copy(sig[:], spkSig[:])
       labeled := Framed(uploadLabel, []byte("bob"), []byte("bob/1"), spk.PublicKey().Bytes())
       row("same signature checked against a LABELED statement", fmt.Sprintf("valid=%v", VerifyXEdDSA(ik, labeled, sig)))

       fmt.Println("── Context registry ──")
       fmt.Printf("  %d labels registered; duplicates/prefix collisions: none (checked at init)\n", len(Registry))
}
