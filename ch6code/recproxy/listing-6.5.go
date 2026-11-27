// Listing 6.5 (part 1) — Lab tool: a TCP proxy that records the raw bytes of
// each direction to files, so the handshake can be dissected without
// packet-capture software.
package main

import (
    "flag"
    "io"
    "log"
    "net"
    "os"
)

func main() {
    listen := flag.String("listen", "127.0.0.1:9443", "")
    target := flag.String("target", "127.0.0.1:8443", "")
    out := flag.String("out", "capture", "file prefix: <out>.c2s / <out>.s2c")
    flag.Parse()
    ln, err := net.Listen("tcp", *listen)
    if err != nil {
        log.Fatal(err)
    }
    c, err := ln.Accept() // one connection is all the lab needs
    if err != nil {
        log.Fatal(err)
    }
    s, err := net.Dial("tcp", *target)
    if err != nil {
        log.Fatal(err)
    }
    c2s, _ := os.Create(*out + ".c2s")
    s2c, _ := os.Create(*out + ".s2c")
    done := make(chan struct{}, 2)
    go func() { io.Copy(io.MultiWriter(s, c2s), c); done <- struct{}{} }()
    go func() { io.Copy(io.MultiWriter(c, s2c), s); done <- struct{}{} }()
    <-done
    c2s.Close()
    s2c.Close()
}
