//go:build lab

// selftest.go — `go run . -selftest`: the checks Chapter 27 prints for the MLS framing parser
// (§27.4), the mTLS policy (§27.7) and the log allowlist (§27.8). Not a book listing.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func runSelfTest() {
	fmt.Println("── MLS framing (Listing 27.8) against OpenMLS 0.7 messages ──")
	selftestMLS()
	fmt.Println("── Service-to-service mTLS (Listing 27.11) ──")
	selftestMTLS()
	fmt.Println("── Log allowlist (Listing 27.12) ──")
	selftestLog()
}

func selftestMLS() {
	raw, err := os.ReadFile("mls_vectors.json")
	if err != nil {
		log.Fatal("mls_vectors.json: ", err, " (run from ch27code/server)")
	}
	var v map[string]string
	json.Unmarshal(raw, &v)
	names := []string{"commit_epoch0", "application_epoch1", "commit_epoch1", "bob_commit_epoch1",
		"public_commit_epoch0", "welcome"}
	wf := map[uint16]string{wirePublic: "PublicMessage ", wirePrivate: "PrivateMessage"}
	ct := map[uint8]string{ctApplication: "application", ctProposal: "proposal", ctCommit: "commit"}
	for _, n := range names {
		b, _ := hex.DecodeString(v[n])
		h, err := ParseMLSHeader(b)
		if err != nil {
			fmt.Printf("  %-22s %4d B  rejected: %v (a Welcome goes to joiners, never through Commit/Message)\n",
				n, len(b), err)
			continue
		}
		fmt.Printf("  %-22s %4d B  %s group=%x… epoch=%d content=%s\n",
			n, len(b), wf[h.WireFormat], h.GroupID[:4], h.Epoch, ct[h.ContentType])
	}
	// The group_id length (16) is one byte, 0x10. Re-encode it as the 2-byte varint 0x40 0x10:
	// same value, non-minimal encoding, which RFC 9420 forbids.
	b, _ := hex.DecodeString(v["commit_epoch0"])
	nm := append(append(append([]byte{}, b[:4]...), 0x40, b[4]), b[5:]...)
	_, e1 := ParseMLSHeader(nm)
	_, e2 := ParseMLSHeader(b[:12])
	fmt.Printf("  same commit with a non-minimal varint length: %v; truncated: %v\n", e1, e2)
}

func selftestMTLS() {
	root := newRoot()
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	services := root.intermediate("Murmur Dev Services CA", []string{".murmur.internal"}, both)
	edge := root.intermediate("Murmur Dev Edge CA", []string{".murmur.test"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	pool := func(cs ...ca) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cs {
			p.AddCert(c.cert)
		}
		return p
	}
	source := func(c tls.Certificate, roots *x509.CertPool) *CertSource {
		s := &CertSource{}
		s.Rotate(c, roots)
		return s
	}
	serialOf := func(c tls.Certificate) string {
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		s := hex.EncodeToString(leaf.SerialNumber.Bytes())
		return "…" + s[len(s)-6:]
	}

	// murmur-push accepts POST /v1/wake from murmur-relay only.
	pushCert := services.leaf("push.murmur.internal", serviceID("murmur-push"), both...)
	push := source(pushCert, pool(root))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/wake", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "woken") })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	var serverErr = make(chan string, 16)
	srv := &http.Server{Handler: Policy{"POST /v1/wake": {serviceID("murmur-relay")}}.Wrap(mux),
		TLSConfig: push.ServerTLS(), ErrorLog: log.New(writerFunc(func(p []byte) {
			s := string(p) // "http: TLS handshake error from ADDR: REASON"
			if i := strings.Index(s, "error from "); i >= 0 {
				if j := strings.Index(s[i:], ": "); j >= 0 {
					s = s[i+j+2:]
				}
			}
			select {
			case serverErr <- strings.TrimSpace(s):
			default:
			}
		}), "", 0)}
	go srv.ServeTLS(ln, "", "")
	addr := ln.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	call := func(label string, client *CertSource, expect string) {
		for len(serverErr) > 0 {
			<-serverErr
		}
		resp, err := client.Client("push.murmur.internal", expect, dial).Post(
			"https://push.murmur.internal/v1/wake", "application/json", nil)
		if err != nil {
			msg := err.Error()
			if i := strings.LastIndex(msg, ": "); i >= 0 && strings.Contains(msg, "remote error") {
				msg = strings.TrimPrefix(msg[i+2:], "tls: ")
			} else if i := strings.Index(msg, "server identity"); i >= 0 {
				msg = msg[i:]
			}
			fmt.Printf("  %-44s ERROR %s\n", label+":", msg)
			if msg != "bad certificate" { // the client refused; the server's view adds nothing
				return
			}
			select {
			case s := <-serverErr:
				fmt.Printf("      server: %s\n", s)
			case <-time.After(200 * time.Millisecond):
			}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("  %-44s %d %s  (server cert serial %s)\n", label+":", resp.StatusCode,
			strings.TrimSpace(string(body)), serialOf(*push.cert.Load()))
	}

	relay := source(services.leaf("relay.murmur.internal", serviceID("murmur-relay"), both...), pool(root))
	api := source(services.leaf("api.murmur.internal", serviceID("murmur-api"), both...), pool(root))
	call("murmur-relay → murmur-push", relay, serviceID("murmur-push"))
	call("murmur-api → murmur-push (not on the route)", api, serviceID("murmur-push"))
	call("relay expecting murmur-auth at that address", relay, serviceID("murmur-auth"))

	edgeClient := source(edge.leaf("relay.murmur.test", serviceID("murmur-relay"), x509.ExtKeyUsageServerAuth), pool(root))
	call("client presenting an Edge CA certificate", edgeClient, serviceID("murmur-push"))

	two := services.leaf("relay.murmur.internal", serviceID("murmur-relay"), both...)
	leaf, _ := x509.ParseCertificate(two.Certificate[0])
	u2, _ := url.Parse(serviceID("murmur-api"))
	leaf.URIs = append(leaf.URIs, u2)
	der, _ := x509.CreateCertificate(randReader{}, leaf, services.cert, leaf.PublicKey, services.key)
	two.Certificate[0] = der
	call("client cert with two SPIFFE IDs", source(two, pool(root)), serviceID("murmur-push"))

	push.Rotate(services.leaf("push.murmur.internal", serviceID("murmur-push"), both...), nil)
	call("after murmur-push renews its certificate", relay, serviceID("murmur-push"))

	newRoot2 := newRoot()
	push.Rotate(*push.cert.Load(), pool(newRoot2))
	call("after push's bundle drops the old root", relay, serviceID("murmur-push"))
	srv.Close()
}

func selftestLog() {
	var buf bytes.Buffer
	lg := NewSafeLogger(&buf)
	p := Pseudonym{DailyKey: func(time.Time) []byte { return []byte("selftest daily key") }}
	h := AccessLog(lg, p, "POST /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		if slot, ok := r.Context().Value(slotKey{}).(*Caller); ok {
			slot.Device = "dev-f115535e8a5d5686"
		}
		lg.Info("debug", "push_token", "apns-token-bob", "body", "the eagle lands at nine")
		w.WriteHeader(202)
	})
	r, _ := http.NewRequest("POST", "https://api.murmur.test/v1/messages", strings.NewReader("{}"))
	r.RemoteAddr = "203.0.113.7:51234"
	r.Header.Set("Authorization", "DPoP eyJhbGciOiJFUzI1NiJ9.e30.sig")
	h(httptestRecorder{}, r)
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, "msg=req") {
			fmt.Println("  " + line)
		}
	}
	leaked := false
	for _, s := range []string{"203.0.113.7", "eyJ", "apns-token", "eagle", "dev-f115"} {
		leaked = leaked || strings.Contains(buf.String(), s)
	}
	fmt.Printf("  IP, token, push token, body or raw device ID written: %v\n", leaked)
}

type writerFunc func([]byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

type httptestRecorder struct{}

func (httptestRecorder) Header() http.Header         { return http.Header{} }
func (httptestRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (httptestRecorder) WriteHeader(int)             {}

type randReader struct{}

func (randReader) Read(b []byte) (int, error) { randRead(b); return len(b), nil }
