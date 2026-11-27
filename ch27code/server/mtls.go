// mtls.go
// Listing 27.11 — Go: service-to-service mTLS. Every internal service has a
// SPIFFE ID (spiffe://murmur.internal/service/<name>) in a 30-day certificate
// from the Services CA (Ch 4), renewed at two-thirds of its lifetime WITHOUT a
// restart. Servers authorize callers by SPIFFE ID per route, default deny;
// clients check the SERVER's SPIFFE ID, not just its DNS name, so a compromised
// service cannot impersonate another one it shares a CA with.
package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "net"
    "net/http"
    "net/url"
    "strings"
    "sync/atomic"
    "time"
)

const trustDomain = "murmur.internal"

// CertSource holds the current certificate and trust bundle; Rotate swaps them
// atomically. In production a renewer (SPIRE agent, cert-manager, or the Ch 4
// tool on a timer) calls it.
type CertSource struct {
    cert  atomic.Pointer[tls.Certificate]
    roots atomic.Pointer[x509.CertPool]
}

func (s *CertSource) Rotate(c tls.Certificate, roots *x509.CertPool) {
    s.cert.Store(&c)
    if roots != nil {
        s.roots.Store(roots)
    }
}

// SPIFFEID returns the single SPIFFE URI SAN of a verified leaf, or an error.
func SPIFFEID(leaf *x509.Certificate) (string, error) {
    // exactly one identity per certificate, or authorization is ambiguous
    if len(leaf.URIs) != 1 {
        return "", errors.New("certificate must carry exactly one SPIFFE ID")
    }
    u := leaf.URIs[0]
    if u.Scheme != "spiffe" || u.Host != trustDomain || !strings.HasPrefix(
        u.Path, "/service/") ||
        u.RawQuery != "" || u.Fragment != "" || u.User != nil {
        return "", errors.New("not a Murmur service identity: " + u.String())
    }
    return u.String(), nil
}

// verifyChain checks the peer against the CURRENT trust bundle (so bundle
// rotation takes effect for new handshakes immediately) and returns its SPIFFE
// ID.
func (s *CertSource) verifyChain(cs tls.ConnectionState,
    eku x509.ExtKeyUsage) (string, error) {
    if len(cs.PeerCertificates) == 0 {
        return "", errors.New("no peer certificate")
    }
    inter := x509.NewCertPool()
    for _, c := range cs.PeerCertificates[1:] {
        inter.AddCert(c)
    }
    if _,
        err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
        Roots: s.roots.Load(),
        Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
        return "", err
    }
    return SPIFFEID(cs.PeerCertificates[0])
}

// ServerTLS: TLS 1.3 only, client certificate mandatory, verified in
// VerifyConnection. (RequireAnyClientCert + our own verification lets the trust
// bundle rotate at runtime.)
func (s *CertSource) ServerTLS() *tls.Config {
    return &tls.Config{
        MinVersion:     tls.VersionTLS13,
        ClientAuth:     tls.RequireAnyClientCert,
        GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate,
            error) { return s.cert.Load(), nil },
        VerifyConnection: func(cs tls.ConnectionState) error {
            _, err := s.verifyChain(cs, x509.ExtKeyUsageClientAuth)
            return err
        },
    }
}

// ClientTLS: normal chain and DNS-name verification against the CURRENT bundle,
// plus a check of the SERVER's SPIFFE ID. Build a fresh config per connection
// (see Client) so a rotated certificate or bundle is used by the next dial.
func (s *CertSource) ClientTLS(serverName, expectServer string) *tls.Config {
    return &tls.Config{
        MinVersion:           tls.VersionTLS13,
        RootCAs:              s.roots.Load(),
        ServerName:           serverName,
        GetClientCertificate: func(*tls.CertificateRequestInfo) (
            *tls.Certificate, error) { return s.cert.Load(), nil },
        VerifyConnection: func(cs tls.ConnectionState) error {
            if len(cs.PeerCertificates) == 0 {
                return errors.New("no server certificate")
            }
            id, err := SPIFFEID(cs.PeerCertificates[0])
            if err != nil {
                return err
            }
            if id != expectServer {
                return errors.New(
                    "server identity " + id + ", expected " + expectServer)
            }
            return nil
        },
    }
}

// Client returns an HTTP client for one internal service.
func (s *CertSource) Client(serverName, expectServer string,
    dial func(ctx context.Context, network, addr string) (net.Conn,
    error)) *http.Client {
    return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
        DialTLSContext: func(ctx context.Context, network,
        addr string) (net.Conn, error) {
            raw, err := dial(ctx, network, addr)
            if err != nil {
                return nil, err
            }
            c := tls.Client(raw, s.ClientTLS(serverName, expectServer))
            if err := c.HandshakeContext(ctx); err != nil {
                raw.Close()
                return nil, err
            }
            return c, nil
        }}}
}

// Policy: route → allowed caller IDs. Anything not listed is denied.
type Policy map[string][]string

func (p Policy) Wrap(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // already verified in the handshake
        id, err := SPIFFEID(r.TLS.PeerCertificates[0])
        allowed := false
        for _, a := range p[r.Method+" "+r.URL.Path] {
            allowed = allowed || (err == nil && a == id)
        }
        if !allowed {
            writeErr(w, 403, "FORBIDDEN", false)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func serviceID(name string) string {
    return (&url.URL{Scheme: "spiffe", Host: trustDomain,
        Path: "/service/" + name}).String()
}
