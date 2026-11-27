// Listing 5.6 — Lab harness: serve each bad chain on its own port, then probe
// with clients.
//
// go run . serve -cases ../cases # ports 8441… in the order printed
//     go run . probe -cases ../cases            # prints the validation matrix
package main

import (
    "crypto/tls"
    "crypto/x509"
    "flag"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strings"
    "time"
)

var cases = []string{"good", "expired", "not-yet-valid", "wrong-host",
    "wrong-eku",
    "missing-intermediate", "wildcard-multi-label", "long-lived",
    "ca-false-intermediate", "self-signed"}

const host = "api.murmur.test"

func port(i int) string { return fmt.Sprintf("127.0.0.1:%d", 8441+i) }

func serve(dir string) {
    for i, c := range cases {
        cert, err := tls.LoadX509KeyPair(filepath.Join(dir, c+".chain.pem"),
            filepath.Join(dir, c+".key.pem"))
        if err != nil {
            panic(err)
        }
        ln, err := tls.Listen("tcp", port(i),
            &tls.Config{Certificates: []tls.Certificate{cert}})
        if err != nil {
            panic(err)
        }
        fmt.Printf("%-22s https://%s  (connect with SNI %s)\n", c, port(i),
            host)
        go func() {
            for {
                conn, err := ln.Accept()
                if err != nil {
                    return
                }
                go func() {
                    defer conn.Close()
                    _ = conn.(*tls.Conn).Handshake()
                    conn.Write([]byte(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
                }()
            }
        }()
    }
    select {}
}

func try(cfg *tls.Config, addr string) string {
    d := &net.Dialer{Timeout: 3 * time.Second}
    conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
    if err != nil {
        msg := err.Error()
        msg = strings.TrimPrefix(msg, "tls: failed to verify certificate: ")
        if len(msg) > 60 {
            msg = msg[:57] + "..."
        }
        return "REJECT  " + msg
    }
    conn.Close()
    return "ACCEPT"
}

func probe(dir string) {
    pemBytes, err := os.ReadFile(filepath.Join(dir, "root.pem"))
    if err != nil {
        panic(err)
    }
    roots := x509.NewCertPool()
    roots.AppendCertsFromPEM(pemBytes)
    // One case per block, so each line fits an 80-column terminal.
    for i, c := range cases {
        fmt.Println(c)
        fmt.Printf("  correct  %s\n", try(correctConfig(roots, host), port(i)))
        fmt.Printf("  broken   %s\n", try(brokenConfig(roots, host), port(i)))
    }
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("usage: serve|probe -cases DIR")
        os.Exit(2)
    }
    fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
    dir := fs.String("cases", "../cases", "directory from gen_bad_certs.py")
    fs.Parse(os.Args[2:])
    if os.Args[1] == "serve" {
        serve(*dir)
    } else {
        probe(*dir)
    }
}
