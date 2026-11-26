// main.go
// Listing 26.4 — Go: lab — boot the empty Murmur stack locally. Edge services (auth, api) serve
// TLS 1.3 on *.murmur.test from the dev Edge CA; internal services (relay, push) accept only
// mTLS from allowlisted SPIFFE IDs. A probe client pins the Edge CA's SPKI and checks health.
package main

import (
       "context"
       "crypto/tls"
       "crypto/x509"
       "encoding/json"
       "fmt"
       "io"
       "log"
       "net"
       "net/http"
       "strings"
       "time"
)

var quiet = log.New(io.Discard, "", 0) // handshake failures are expected in the negative checks

var addrs = map[string]string{ // what DNS / docker-compose networking would resolve
       "auth.murmur.test": "127.0.0.1:18443", "api.murmur.test": "127.0.0.1:18444",
       "relay.murmur.internal": "127.0.0.1:19001", "push.murmur.internal": "127.0.0.1:19002",
}

func dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
       return func(ctx context.Context, network, addr string) (net.Conn, error) {
              host, _, err := net.SplitHostPort(addr)
              if err != nil {
                     return nil, err
              }
              target, ok := addrs[host]
              if !ok { // unknown name: fail, never dial "" (which would mean localhost)
                     return nil, fmt.Errorf("no such host %q in dev stack", host)
              }
              return (&net.Dialer{}).DialContext(ctx, network, target)
       }
}

// internal mTLS server: requires a client cert from the Services CA and an allowlisted SPIFFE ID.
func internalServer(name string, cert tls.Certificate, services *x509.CertPool, allowed ...string) {
       mux := http.NewServeMux()
       mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
              leaf := r.TLS.PeerCertificates[0]
              if len(leaf.URIs) != 1 { // exactly one SPIFFE ID, or no entry
                     http.Error(w, "403 no SPIFFE ID", http.StatusForbidden)
                     return
              }
              id := leaf.URIs[0].String()
              for _, a := range allowed {
                     if id == a {
                            fmt.Fprintf(w, `{"service":%q,"status":"ok","caller":%q}`, name, id)
                            return
                     }
              }
              http.Error(w, "403 caller "+id+" not allowed", http.StatusForbidden)
       })
       srv := &http.Server{Addr: addrs[name], Handler: mux, ErrorLog: quiet, TLSConfig: &tls.Config{
              Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert,
              ClientCAs: services, MinVersion: tls.VersionTLS13}}
       go srv.ListenAndServeTLS("", "")
}

func internalClient(cert tls.Certificate, roots *x509.CertPool) *http.Client {
       return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: dialer(),
              TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
}

func get(c *http.Client, url string) string {
       resp, err := c.Get(url)
       if err != nil {
              e := err.Error()
              if i := strings.LastIndex(e, ": "); i > 0 {
                     e = e[i+2:]
              }
              return "ERROR " + e
       }
       defer resp.Body.Close()
       b, _ := io.ReadAll(resp.Body)
       return strings.TrimSpace(string(b))
}

func main() {
       root := newRoot()
       services := root.intermediate("Murmur Dev Services CA", []string{".murmur.internal"},
              []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
       edge := root.intermediate("Murmur Dev Edge CA", []string{".murmur.test"},
              []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
       roots := x509.NewCertPool()
       roots.AddCert(root.cert)
       svcPool := x509.NewCertPool()
       svcPool.AddCert(root.cert)
       spiffe := func(s string) string { return "spiffe://murmur.internal/service/" + s }
       both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

       // internal services
       internalServer("relay.murmur.internal", services.leaf("relay.murmur.internal", spiffe("murmur-relay"), both...), svcPool, spiffe("murmur-api"))
       internalServer("push.murmur.internal", services.leaf("push.murmur.internal", spiffe("murmur-push"), both...), svcPool, spiffe("murmur-api"), spiffe("murmur-relay"))

       // edge services
       apiInternal := internalClient(services.leaf("api.murmur.internal", spiffe("murmur-api"), both...), roots)
       edgeMux := func(name string) *http.ServeMux {
              m := http.NewServeMux()
              m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
                     out := map[string]string{"service": name, "status": "ok"}
                     if name == "murmur-api" {
                            out["relay"] = get(apiInternal, "https://relay.murmur.internal/healthz")
                            out["push"] = get(apiInternal, "https://push.murmur.internal/healthz")
                     }
                     json.NewEncoder(w).Encode(out)
              })
              m.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
                     fmt.Fprint(w, `{"issuer":"https://auth.murmur.test","authorization_endpoint":"https://auth.murmur.test/authorize"}`)
              })
              return m
       }
       for host, name := range map[string]string{"auth.murmur.test": "murmur-auth", "api.murmur.test": "murmur-api"} {
              srv := &http.Server{Addr: addrs[host], Handler: edgeMux(name), ErrorLog: quiet, TLSConfig: &tls.Config{
                     Certificates: []tls.Certificate{edge.leaf(host, "", x509.ExtKeyUsageServerAuth)}, MinVersion: tls.VersionTLS13}}
              go srv.ListenAndServeTLS("", "")
       }
       time.Sleep(300 * time.Millisecond)

       // ── the probe: what the Android/iOS debug builds do ──
       pin := spkiPin(edge.cert)
       probe := func(pins []string) *http.Client {
              return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: dialer(),
                     TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13,
                            VerifyConnection: func(cs tls.ConnectionState) error { // pinning ON TOP of chain validation (Ch 8)
                                   for _, chain := range cs.VerifiedChains {
                                          for _, c := range chain[1:] {
                                                 for _, p := range pins {
                                                        if spkiPin(c) == p {
                                                               return nil
                                                        }
                                                 }
                                          }
                                   }
                                   return fmt.Errorf("pin mismatch")
                            }}}}
       }
       fmt.Println("── Boot the empty stack ──")
       fmt.Println("  Edge CA SPKI pin (compiled into debug builds):", pin)
       ok := probe([]string{pin})
       fmt.Println("  client → auth  /.well-known/openid-configuration:", get(ok, "https://auth.murmur.test/.well-known/openid-configuration"))
       fmt.Println("  client → api   /healthz:", get(ok, "https://api.murmur.test/healthz"))
       fmt.Println("── Negative checks ──")
       fmt.Println("  client with a wrong pin → api:     ", get(probe([]string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}), "https://api.murmur.test/healthz"))
       fmt.Println("  client → unknown dev name:         ", get(ok, "https://admin.murmur.test/healthz"))
       fmt.Println("  client straight to the relay:      ", get(probe([]string{pin}), "https://relay.murmur.internal/healthz"))
       pushAsCaller := internalClient(services.leaf("push.murmur.internal", spiffe("murmur-push"), both...), roots)
       fmt.Println("  murmur-push (not allowlisted) → relay:", get(pushAsCaller, "https://relay.murmur.internal/healthz"))
       fmt.Println("  services CA cannot issue edge names:", func() string {
              c := services.leaf("api.murmur.test", "", x509.ExtKeyUsageServerAuth)
              leaf, _ := x509.ParseCertificate(c.Certificate[0])
              inter := x509.NewCertPool()
              inter.AddCert(services.cert)
              _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "api.murmur.test"})
              if err == nil {
                     return "verified (!)"
              }
              return "rejected: " + err.Error()
       }())
}
