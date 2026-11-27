// Listing 6.2 — Go: a TLS 1.3-only server with explicit configuration and a
// lab-only key log.
//
// SSLKEYLOGFILE=keys.log go run ./server -cert murmur-api.crt -chain
// services-ca.crt -key murmur-api.key
package main

import (
    "crypto/tls"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    certFile := flag.String("cert", "murmur-api.crt", "leaf certificate (PEM)")
    chainFile := flag.String("chain", "services-ca.crt",
        "intermediate(s) to send (PEM)")
    keyFile := flag.String("key", "murmur-api.key", "leaf private key (PEM)")
    addr := flag.String("addr", "127.0.0.1:8443", "listen address")
    flag.Parse()

    // Leaf + intermediate in one PEM bundle: the server must send the full
    // chain (Chapter 5).
    bundle := mustRead(*certFile) + mustRead(*chainFile)
    cert, err := tls.X509KeyPair([]byte(bundle), []byte(mustRead(*keyFile)))
    if err != nil {
        log.Fatal(err)
    }

    cfg := &tls.Config{
        MinVersion:   tls.VersionTLS13, // refuse TLS 1.2 and below entirely
        MaxVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{cert},
        // TLS 1.3 cipher suites are not configurable in Go: AES-128-GCM,
        // AES-256-GCM and ChaCha20-Poly1305 are always enabled, which is the
        // point — there are no bad ones. Key exchange groups, in preference
        // order (Go 1.24+ also offers the PQ hybrid):
        CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519,
            tls.CurveP256},
        NextProtos:       []string{"http/1.1"},
    }

    // ⚠️ LAB ONLY: writing traffic secrets to a file lets anyone holding the
    // file decrypt the traffic. Guard it so it can never be enabled by accident
    // in production.
    if path := os.Getenv("SSLKEYLOGFILE"); path != "" {
        if os.Getenv("MURMUR_ENV") == "production" {
            log.Fatal("refusing to write TLS key log in production")
        }
        f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
        if err != nil {
            log.Fatal(err)
        }
        cfg.KeyLogWriter = f
        log.Printf("⚠️  writing TLS secrets to %s (lab only)", path)
    }

    srv := &http.Server{
        Addr:      *addr,
        TLSConfig: cfg,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprintf(w, "hello from murmur-api over %s\n",
            tlsVersion(r.TLS.Version))
        }),
    }
    log.Printf("listening on https://%s", *addr)
    log.Fatal(srv.ListenAndServeTLS("", "")) // certificates come from TLSConfig
}

func tlsVersion(v uint16) string {
    if v == tls.VersionTLS13 {
        return "TLS 1.3"
    }
    return fmt.Sprintf("0x%04x", v)
}

func mustRead(p string) string {
    b, err := os.ReadFile(p)
    if err != nil {
        log.Fatal(err)
    }
    return string(b)
}
