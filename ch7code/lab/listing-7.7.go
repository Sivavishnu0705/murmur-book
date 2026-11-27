// Listing 7.7 — Go: demo driver for Listings 7.1, 7.2 and 7.5 (resumption, Too
// Early, exporters).
package main

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "log"
    "net"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "sync/atomic"
    "time"
)

func must[T any](v T, err error) T {
    if err != nil {
        log.Fatal(err)
    }
    return v
}

func main() {
    pki := os.Args[1]
    read := func(n string) []byte { return must(os.ReadFile(pki + "/" + n)) }
    cert := must(tls.X509KeyPair(append(read("murmur-api.crt"),
        read("services-ca.crt")...), read("murmur-api.key")))
    roots := x509.NewCertPool()
    roots.AppendCertsFromPEM(read("root.crt"))

    // ---- 7.1 resumption ----
    ring := NewTicketKeyRing(3)
    srvCfg := ServerConfig(cert, ring)
    ln := must(tls.Listen("tcp", "127.0.0.1:0", srvCfg))
    serverBindings := make(chan []byte, 8)
    go func() {
        for {
            c, err := ln.Accept()
            if err != nil {
                return
            }
            go func(c net.Conn) {
                tc := c.(*tls.Conn)
                if tc.Handshake() == nil {
                    serverBindings <- must(TLSExporterBinding(
                        tc.ConnectionState()))
                }
                // tickets are sent right after the handshake, before this
                tc.Write([]byte("ok"))
                buf := make([]byte, 1)
                tc.Read(buf)
                tc.Close()
            }(c)
        }
    }()
    cliCfg := &tls.Config{RootCAs: roots,
        ServerName: "murmur-api.murmur.internal",
        MinVersion: tls.VersionTLS13,
        ClientSessionCache: tls.NewLRUClientSessionCache(8)}
    dial := func(label string) {
        c := must(tls.Dial("tcp", ln.Addr().String(), cliCfg))
        c.Write([]byte("x"))
        buf := make([]byte, 2)
        c.Read(buf) // a Read processes the NewSessionTicket that precedes "ok"
        cs := c.ConnectionState()
        cb := must(TLSExporterBinding(cs))
        fmt.Printf(
            "%-14s resumed=%-5v  tls-exporter(client)=%x…  (server)=%x…\n",
            label, cs.DidResume, cb[:8], (<-serverBindings)[:8])
        c.Close()
    }
    dial("connection 1")
    dial("connection 2")
    ring.Rotate()
    ring.Apply(srvCfg)
    dial("after 1 rotate")
    for i := 0; i < 3; i++ {
        ring.Rotate()
    }
    ring.Apply(srvCfg)
    dial("after 4 rotates")

    // ---- 7.2 Too Early + idempotency ----
    var executed atomic.Int32
    transfer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet {
            fmt.Fprintln(w, "balance: 1200")
            return
        }
        executed.Add(1)
        fmt.Fprintf(w, "transfer #%d done\n", executed.Load())
    })
    h := RejectEarlyUnsafe(NewIdempotency(24 * time.Hour).Wrap(transfer))
    send := func(desc, method, early, key string) {
        req := httptest.NewRequest(method, "/transfer",
            bytes.NewBufferString(`{"amt":500}`))
        if early != "" {
            req.Header.Set("Early-Data", early)
        }
        if key != "" {
            req.Header.Set("Idempotency-Key", key)
        }
        rec := httptest.NewRecorder()
        h.ServeHTTP(rec, req)
        fmt.Printf("%-38s → %d %-28s executed=%d\n", desc, rec.Code,
            strings.TrimSpace(rec.Body.String()), executed.Load())
    }
    fmt.Println()
    send("POST in 0-RTT (Early-Data: 1)", "POST", "1", "k-7f3a")
    send("POST after handshake", "POST", "", "k-7f3a")
    send("same POST replayed (same key)", "POST", "", "k-7f3a")
    send("POST without Idempotency-Key", "POST", "", "")
    send("GET in 0-RTT", "GET", "1", "")
}
