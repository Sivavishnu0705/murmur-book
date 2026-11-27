//go:build lab

// lab_main.go — the lab server as of Chapter 31 (build tag `lab` only, Listing 31.8's fix for
// T-23): Chapter 30's main.go plus the malicious-server mode of Listing 31.4, whose control
// port is published in ready.json as "evil". Build: go build -tags lab -o murmur-lab .
// Chapter 30's header follows.
// the lab server as of Chapter 30: the KeyPackage directory (Listing 30.4) and the DS
// extensions of Listing 30.5. Before that, as of Chapter 29: sender certificates (Listing 29.1), resumable
// attachment uploads (Listing 29.8), GET /v1/aik/{account}, and relay fan-out computed from the
// AIK-signed device list. Before that, as of Chapter 28: Chapter 27's main.go plus Idempotency-Key on
// every authenticated POST and PUT, and GET /v1/keys/count. Otherwise as in Chapter 27:
// routing and wiring for the lab server. Chapter 27 lists this file
// under "Described only". It runs murmur-auth and murmur-api in one process, each on its own
// TLS 1.3 port under the Chapter 26 dev PKI, on the in-memory store, with:
//   - a dev login at murmur-auth (it trusts the account name in the request, standing in for
//     the browser, PKCE and passkey flows of Chapters 11–14) that issues real ES256 at+jwt
//     access tokens bound to the device's DPoP key;
//   - a lab attestation verifier: a lab key signs the evidence instead of Play Integrity or
//     App Attest (Chapter 9 has the real verifiers);
//   - local HTTP/2 stand-ins for APNs and FCM that check the provider credentials and record
//     what each provider would see.
//
// Usage:
//
//	go run . -selftest        MLS framing, mTLS policy and log allowlist checks (§27.4, §27.7, §27.8)
//	go run . -out DIR         start the lab server; ch27code/lab/lab.py drives it
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	authOrigin = "https://auth.murmur.test"
	apiOrigin  = "https://api.murmur.test"
	tokenTTL   = 5 * time.Minute
	allScopes  = "messages:send messages:read prekeys:write keys:write attachments:write devices:enroll devices:revoke"
	labAndroid = "example.murmur:SHA256:8F:1C:…"
	labIOS     = "TEAMID1234.example.murmur"
)

func main() { // lab build
	out := flag.String("out", "", "lab directory for PKI files, logs and the store dump")
	selftest := flag.Bool("selftest", false, "run the MLS framing, mTLS and logging self-tests")
	flag.Parse()
	switch {
	case *selftest:
		runSelfTest()
	case *out != "":
		runLab(*out)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// ── lab attestation ──

// labAttestation verifies the lab's stand-in evidence: {"app_id", "sig"}, where sig is an
// ECDSA P-256 signature (raw r‖s) by the lab attestation key over
// SHA-256("lab-attestation\0" ‖ app_id ‖ "\0" ‖ nonce ‖ "\0" ‖ SPKI of the DPoP key).
type labAttestation struct {
	key           *ecdsa.PublicKey
	keyInHardware bool
}

func (l labAttestation) Verify(evidence, nonce, spki []byte) (Verdict, error) {
	var e struct {
		AppID string `json:"app_id"`
		Sig   []byte `json:"sig"`
	}
	if json.Unmarshal(evidence, &e) != nil || len(e.Sig) != 64 {
		return Verdict{}, errors.New("malformed evidence")
	}
	msg := append([]byte("lab-attestation\x00"+e.AppID+"\x00"), nonce...)
	msg = append(append(msg, 0), spki...)
	d := sha256.Sum256(msg)
	if !ecdsa.Verify(l.key, d[:], new(big.Int).SetBytes(e.Sig[:32]), new(big.Int).SetBytes(e.Sig[32:])) {
		return Verdict{}, errors.New("bad evidence signature")
	}
	return Verdict{AppID: e.AppID, KeyInHardware: l.keyInHardware, DeviceIntegrity: true}, nil
}

// ── murmur-auth: dev login and token issuance ──

type AuthServer struct {
	Devices *Registry
	DPoP    *Verifier
	Key     *ecdsa.PrivateKey
	Kid     string
	Clock   func() time.Time
}

func (a *AuthServer) issue(account, device, jkt string, phr bool) string {
	now := a.Clock()
	acr := "pwd"
	if phr {
		acr = "phr"
	}
	jti := make([]byte, 16)
	rand.Read(jti)
	claims := map[string]any{"iss": authOrigin, "aud": apiOrigin, "sub": account, "device_id": device,
		"iat": now.Unix(), "exp": now.Add(tokenTTL).Unix(), "jti": hex.EncodeToString(jti),
		"scope": allScopes, "acr": acr, "auth_time": now.Unix(), "cnf": map[string]string{"jkt": jkt}}
	return es256JWT(a.Key, map[string]any{"typ": "at+jwt", "alg": "ES256", "kid": a.Kid}, claims)
}

// POST /v1/enroll/challenge → {"nonce"}
func (a *AuthServer) Challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]byte{"nonce": a.Devices.Challenge(a.Clock())})
}

// POST /v1/token — DPoP proof required. With a nonce, PoP and attestation it enrolls a new
// device (Listing 27.3); without them it issues a token for the device bound to the proof key.
func (a *AuthServer) Token(w http.ResponseWriter, r *http.Request) {
	now := a.Clock()
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		writeErr(w, 401, "UNAUTHENTICATED", false)
		return
	}
	jkt, err := a.DPoP.Verify(proofs[0], r.Method, r.URL.EscapedPath(), "", now)
	if err != nil {
		writeErr(w, 401, "UNAUTHENTICATED", false)
		return
	}
	var q struct {
		Account     string `json:"account"`
		Platform    string `json:"platform"`
		PHR         bool   `json:"phr"`
		PushToken   string `json:"push_token"`
		Nonce       []byte `json:"nonce"`
		PoP         []byte `json:"pop"`
		Attestation []byte `json:"attestation"`
	}
	if !readJSON(w, r, 16<<10, &q) || q.Account == "" {
		return
	}
	var dev Device
	if q.Nonce != nil {
		key, err := proofKey(proofs[0])
		if err != nil {
			writeErr(w, 400, "MALFORMED", false)
			return
		}
		d, err := a.Devices.Enroll(EnrollRequest{Account: q.Account, Platform: q.Platform, Nonce: q.Nonce,
			DPoPKey: key, Jkt: jkt, PoP: q.PoP, Attestation: q.Attestation, StepUpOK: q.PHR}, now)
		switch {
		case errors.Is(err, ErrStepUp):
			writeErr(w, 403, "STEP_UP_REQUIRED", false)
			return
		case err != nil:
			writeErr(w, 403, "FORBIDDEN", false) // nonce, PoP, attestation, device limit: one answer
			return
		}
		dev = *d
	} else {
		d, ok := a.Devices.ByJkt(q.Account, jkt)
		if !ok {
			writeErr(w, 401, "UNAUTHENTICATED", false)
			return
		}
		dev = d
	}
	if q.PushToken != "" {
		a.Devices.SetPushToken(dev.ID, q.PushToken)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"access_token": a.issue(q.Account, dev.ID, jkt, q.PHR),
		"token_type": "DPoP", "expires_in": int(tokenTTL.Seconds()), "device_id": dev.ID})
}

// proofKey extracts the public key from a DPoP proof that Verifier.Verify already accepted.
func proofKey(proof string) (*ecdsa.PublicKey, error) {
	h, _, _ := strings.Cut(proof, ".")
	hb, err := b64.DecodeString(h)
	if err != nil {
		return nil, err
	}
	var hdr struct{ JWK JWK }
	if json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("bad header")
	}
	return hdr.JWK.Public()
}

// POST /v1/devices/revoke  (scope devices:revoke → step-up): {"device"}
func revokeHandler(reg *Registry, clock func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Device string `json:"device"`
		}
		if !readJSON(w, r, 1<<10, &q) {
			return
		}
		if err := reg.Revoke(CallerFrom(r).Account, q.Device, clock()); err != nil {
			writeErr(w, 404, "NOT_FOUND", false)
			return
		}
		w.WriteHeader(204)
	}
}

// ── local stand-ins for APNs and FCM ──

type providerLog struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *providerLog) printf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, f+"\n", a...)
}

func verifyES256JWT(tok string, key *ecdsa.PublicKey) (map[string]any, bool) {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil, false
	}
	sig, err := b64.DecodeString(p[2])
	d := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err != nil || len(sig) != 64 ||
		!ecdsa.Verify(key, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, false
	}
	cb, _ := b64.DecodeString(p[1])
	var c map[string]any
	return c, json.Unmarshal(cb, &c) == nil
}

func verifyRS256JWT(tok string, key *rsa.PublicKey) (map[string]any, bool) {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil, false
	}
	sig, err := b64.DecodeString(p[2])
	d := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, d[:], sig) != nil {
		return nil, false
	}
	cb, _ := b64.DecodeString(p[1])
	var c map[string]any
	return c, json.Unmarshal(cb, &c) == nil
}

// fakeAPNs checks the provider JWT (ES256, team ID, key ID) and the topic, like Apple does.
func fakeAPNs(plog *providerLog, key *ecdsa.PublicKey, teamID, topic string, dead map[string]bool) *httptest.Server {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		tok, _ := strings.CutPrefix(r.Header.Get("authorization"), "bearer ")
		c, ok := verifyES256JWT(tok, key)
		if !ok || c["iss"] != teamID || r.Header.Get("apns-topic") != topic {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"reason":"InvalidProviderToken"}`)
			return
		}
		devTok := strings.TrimPrefix(r.URL.Path, "/3/device/")
		if dead[devTok] {
			plog.printf("APNs %s %s → 410 Unregistered", r.Proto, r.URL.Path)
			w.WriteHeader(410)
			fmt.Fprint(w, `{"reason":"Unregistered"}`)
			return
		}
		plog.printf("APNs %s %s push-type=%s collapse-id=%s payload=%s", r.Proto, r.URL.Path,
			r.Header.Get("apns-push-type"), r.Header.Get("apns-collapse-id"), body)
		w.WriteHeader(200)
	}))
	s.EnableHTTP2 = true
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	return s
}

// fakeFCM runs the OAuth token endpoint (RFC 7523 JWT bearer grant, RS256) and the HTTP v1 send
// endpoint, which accepts only access tokens it issued.
func fakeFCM(plog *providerLog, key *rsa.PublicKey, clientEmail string) *httptest.Server {
	var mu sync.Mutex
	issued := map[string]bool{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			r.ParseForm()
			c, ok := verifyRS256JWT(r.PostForm.Get("assertion"), key)
			if !ok || c["iss"] != clientEmail ||
				r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				w.WriteHeader(400)
				return
			}
			t := make([]byte, 16)
			rand.Read(t)
			at := "ya29.lab-" + hex.EncodeToString(t)
			mu.Lock()
			issued[at] = true
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"access_token": at, "expires_in": 3600})
			return
		}
		at, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := issued[at]
		mu.Unlock()
		if !ok {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		plog.printf("FCM  %s %s payload=%s", r.Proto, r.URL.Path, body)
		fmt.Fprint(w, `{"name":"projects/murmur-lab/messages/1"}`)
	}))
	s.EnableHTTP2 = true
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	return s
}

// ── the lab server ──

func writePEM(path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
}

func listenTLS(cert tls.Certificate, h http.Handler) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: h, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	go srv.ServeTLS(ln, "", "")
	return ln.Addr().(*net.TCPAddr).Port
}

func runLab(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	clock := time.Now

	// PKI (Chapter 26): root → Edge CA → auth/api leaves. The client pins the Edge CA's SPKI.
	root := newRoot()
	edge := root.intermediate("Murmur Dev Edge CA", []string{".murmur.test"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	writePEM(filepath.Join(dir, "root.pem"), "CERTIFICATE", root.cert.Raw)

	attestKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(attestKey)
	writePEM(filepath.Join(dir, "lab-attestation-key.pem"), "PRIVATE KEY", der)

	// Registry, store, directory, relay, DS, attachments.
	store := NewMemStore(50, 64<<20, clock)
	reg := NewRegistry()
	reg.Verifiers["android"] = labAttestation{&attestKey.PublicKey, true}
	reg.Verifiers["ios"] = labAttestation{&attestKey.PublicKey, false}
	reg.AppIDs["android"], reg.AppIDs["ios"] = labAndroid, labIOS
	go func() { // revocation feed consumer (pub/sub in production): nothing to do in one process
		for range reg.Feed {
		}
	}()

	dpopAPI := &Verifier{Window: 60 * time.Second, Replay: NewReplayCache(), PublicOrigin: apiOrigin}
	dpopAuth := &Verifier{Window: 60 * time.Second, Replay: NewReplayCache(), PublicOrigin: authOrigin}
	authKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authSrv := &AuthServer{Devices: reg, DPoP: dpopAuth, Key: authKey, Kid: "lab-1", Clock: clock}
	authn := &Authenticator{Issuer: &IssuerConfig{Issuer: authOrigin, Audience: apiOrigin,
		Keys: map[string]*ecdsa.PublicKey{"lab-1": &authKey.PublicKey}, Leeway: 30 * time.Second},
		DPoP: dpopAPI, Devices: reg, Clock: clock}

	// Push: local APNs and FCM stand-ins with real provider credentials.
	pf, err := os.Create(filepath.Join(dir, "push-providers.log"))
	if err != nil {
		log.Fatal(err)
	}
	plog := &providerLog{w: pf}
	apnsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fcmKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	apnsSrv := fakeAPNs(plog, &apnsKey.PublicKey, "TEAMID1234", "example.murmur", map[string]bool{"dead-token": true})
	fcmSrv := fakeFCM(plog, &fcmKey.PublicKey, "push@murmur-lab.iam.gserviceaccount.com")
	gw := &Gateway{Devices: reg, CoalesceWindow: 5 * time.Second, Clock: clock, last: map[string]time.Time{},
		APNs: &APNs{Base: apnsSrv.URL, Topic: "example.murmur", TeamID: "TEAMID1234", KeyID: "LABKEY0001",
			Key: apnsKey, HTTP: apnsSrv.Client(), Clock: clock},
		FCM: &FCM{Base: fcmSrv.URL, TokenURI: fcmSrv.URL + "/token", Project: "murmur-lab",
			ClientEmail: "push@murmur-lab.iam.gserviceaccount.com", Key: fcmKey, HTTP: fcmSrv.Client(), Clock: clock}}
	wake := func(device string) { gw.Wake(device) }

	directory := NewDirectory(store, reg, clock)
	directory.OnLow = wake
	relay := &Relay{Queues: store, Devices: reg, Wake: wake, tokens: map[string][32]byte{},
		byAcct: reg.ByAccount, IPLimits: NewLimiter(600)}
	ds := NewDS(reg, store, store, wake)
	kps := &KeyPackages{single: map[string][][]byte{}, lastResort: map[string][]byte{}, Devices: reg,
		Limiter: NewLimiter(10), Clock: clock}
	akey := make([]byte, 32)
	rand.Read(akey)
	attach := &AttachmentStore{Key: akey, Base: apiOrigin, Clock: clock, blobs: map[string]blob{},
		partial: map[string][]byte{}}
	// Chapter 29: the relay's required device set is the account's AIK-signed device list.
	relay.byAcct = directory.ListedDevices
	certKey, err := newEd25519()
	if err != nil {
		log.Fatal(err)
	}
	certs := &SenderCerts{Key: certKey, Directory: directory, Clock: clock}
	pub, _ := x509.MarshalPKIXPublicKey(certKey.Public())
	writePEM(filepath.Join(dir, "sender-cert-key.pub"), "PUBLIC KEY", pub) // compiled into the apps
	reg.OnRevoke = append(reg.OnRevoke,
		func(d *Device) { directory.Forget(d.ID) },
		func(d *Device) { store.ForgetDevice(d.ID) },
		func(d *Device) { kps.Forget(d.ID) })

	// Logs: allowlisted fields only, pseudonymous device IDs under a daily key.
	lf, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		log.Fatal(err)
	}
	slog := NewSafeLogger(lf)
	dailyKey := make([]byte, 32)
	rand.Read(dailyKey)
	pseud := Pseudonym{DailyKey: func(time.Time) []byte { return dailyKey }}

	af, err := os.Create(filepath.Join(dir, "auth.log")) // murmur-auth is a separate service
	if err != nil {
		log.Fatal(err)
	}
	authLog := NewSafeLogger(af)

	// Listing 31.4: the malicious-server mode. Its closures reach into the server's internals the
	// way a compromised server could; the honest handlers are only wrapped, never changed.
	evil := NewEvil()
	evilPort := evil.Serve(
		func(account, jkt string, ik []byte) (string, string) { // invent a device: no attestation
			id := reg.inventDevice(account, jkt, clock())
			directory.mu.Lock()
			directory.iks[id] = ik
			directory.mu.Unlock()
			store.PutIdentity(context.Background(), account, id, ik)
			return id, authSrv.issue(account, id, jkt, true)
		},
		func(device string, body []byte) { // replay: enqueue under a fresh GUID
			guid := make([]byte, 16)
			rand.Read(guid)
			if store.Enqueue(context.Background(), device, guid, body, envelopeTTL) == nil {
				wake(device)
			}
		},
		func(device, alertBody string) { gw.pushText(device, alertBody) }, // push text injection
		func(account string, aik []byte) { // replace the AIK the directory serves
			directory.mu.Lock()
			directory.aiks[account] = aik
			directory.mu.Unlock()
		})

	authMux, apiMux := http.NewServeMux(), http.NewServeMux()
	route := func(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
		l := slog
		if mux == authMux {
			l = authLog
		}
		mux.HandleFunc(pattern, AccessLog(l, pseud, pattern, h))
	}
	route(authMux, "POST /v1/enroll/challenge", authSrv.Challenge)
	route(authMux, "POST /v1/token", authSrv.Token)

	ix := &Idempotency{saved: map[string]*savedResponse{}, Clock: clock, TTL: 24 * time.Hour}
	// Chapter 28: every authenticated POST and PUT needs an Idempotency-Key (Listing 28.14).
	// Wrap runs inside Require, so keys are scoped to the authenticated device.
	req := authn.Require
	reqW := func(scope string, h http.HandlerFunc) http.HandlerFunc { return authn.Require(scope, ix.Wrap(h)) }
	route(apiMux, "POST /v1/keys/identity", reqW("keys:write", directory.PutIdentity))
	route(apiMux, "PUT /v1/keys/prekeys", reqW("prekeys:write", directory.PutPrekeys))
	route(apiMux, "GET /v1/keys/count", req("prekeys:write", directory.CountKeys))
	route(apiMux, "GET /v1/keys/bundle/{device}", req("messages:send", evil.WrapBundle(directory.GetBundle)))
	route(apiMux, "PUT /v1/aik", reqW("keys:write", directory.PutAIK))
	route(apiMux, "PUT /v1/devicelist", reqW("keys:write", directory.PutDeviceList))
	route(apiMux, "GET /v1/devicelist/{account}", req("messages:send", evil.WrapDeviceList(directory.GetDeviceList)))
	route(apiMux, "POST /v1/messages", reqW("messages:send", evil.WrapSend(relay.Send)))
	route(apiMux, "POST /v1/sealed", evil.WrapSend(relay.SendSealed)) // no Authorization: sealed sender
	route(apiMux, "PUT /v1/delivery-token", reqW("messages:read", relay.SetDeliveryToken))
	route(apiMux, "GET /v1/messages", req("messages:read", relay.Fetch))
	route(apiMux, "POST /v1/messages/ack", reqW("messages:read", relay.Ack))
	route(apiMux, "POST /v1/devices/revoke", reqW("devices:revoke", revokeHandler(reg, clock)))
	route(apiMux, "PUT /v1/mls/keypackages", reqW("prekeys:write", kps.Upload))
	route(apiMux, "GET /v1/mls/keypackage/{device}", req("messages:send", evil.WrapKeyPackage(kps.Claim)))
	route(apiMux, "GET /v1/mls/keypackages/count", req("prekeys:write", kps.Count))
	route(apiMux, "POST /v1/groups/commit", reqW("messages:send", ds.Commit))
	route(apiMux, "POST /v1/groups/message", reqW("messages:send", ds.Message))
	route(apiMux, "POST /v1/attachments", reqW("attachments:write", attach.Authorize))
	route(apiMux, "GET /v1/sender-certificate", req("messages:send", certs.Issue))
	route(apiMux, "GET /v1/aik/{account}", req("messages:send", directory.GetAIK))
	route(apiMux, "HEAD /cdn/{id}", attach.Offset)
	route(apiMux, "PUT /cdn/{id}", attach.Upload)
	route(apiMux, "GET /cdn/{id}", attach.Download)

	ports := map[string]int{
		"auth": listenTLS(edge.leaf("auth.murmur.test", "", x509.ExtKeyUsageServerAuth), authMux),
		"api":  listenTLS(edge.leaf("api.murmur.test", "", x509.ExtKeyUsageServerAuth), apiMux),
	}
	ready, _ := json.Marshal(map[string]any{"ports": ports, "edge_pin": spkiPin(edge.cert), "evil": evilPort})
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), ready, 0o600); err != nil {
		log.Fatal(err)
	}

	// On SIGTERM: write everything the server holds to store-dump.bin, so the lab can search it
	// for plaintext, then exit.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	fmt.Println("ready")
	<-stop
	dump := store.Dump()
	attach.mu.Lock()
	for _, b := range attach.blobs {
		dump = append(dump, b.data...)
	}
	attach.mu.Unlock()
	os.WriteFile(filepath.Join(dir, "store-dump.bin"), dump, 0o600)
	lf.Close()
	af.Close()
	pf.Close()
	os.Exit(0)
}
