// main.go
// Listing 32.2 — Go: what hybrid post-quantum key exchange costs a TLS 1.3 handshake.
// One server (Go 1.24 defaults, which offer X25519MLKEM768 first), two clients: one limited to
// classical X25519, one with Go's defaults. Every byte each side writes during the handshake is
// counted, the group the server chose is read straight out of the ServerHello's key_share, and
// the handshake is timed on loopback.
package main

import (
       "crypto/ecdsa"
       "crypto/elliptic"
       "crypto/rand"
       "crypto/tls"
       "crypto/x509"
       "crypto/x509/pkix"
       "encoding/binary"
       "fmt"
       "math/big"
       "net"
       "sort"
       "sync"
       "time"
)

// countConn counts the bytes written through it and keeps the first ones (the first flight).
type countConn struct {
       net.Conn
       mu      sync.Mutex
       written int
       first   []byte
}

func (c *countConn) Write(b []byte) (int, error) {
       c.mu.Lock()
       c.written += len(b)
       if len(c.first) < 8192 {
              c.first = append(c.first, b...)
       }
       c.mu.Unlock()
       return c.Conn.Write(b)
}

// serverHelloGroup walks the first TLS record (ServerHello) to the key_share extension (0x0033).
func serverHelloGroup(rec []byte) uint16 {
       if len(rec) < 5+4+2+32+1 || rec[0] != 22 || rec[5] != 2 {
              return 0
       }
       p := rec[5+4:]      // skip record header and handshake header
       p = p[2+32:]        // legacy_version, random
       p = p[1+int(p[0]):] // legacy_session_id_echo
       p = p[2+1:]         // cipher_suite, legacy_compression_method
       ext := p[2 : 2+int(binary.BigEndian.Uint16(p))]
       for len(ext) >= 4 {
              typ, n := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
              if typ == 0x0033 && n >= 2 {
                     return binary.BigEndian.Uint16(ext[4:])
              }
              ext = ext[4+n:]
       }
       return 0
}

var groupName = map[uint16]string{0x001d: "x25519", 0x11ec: "X25519MLKEM768", 0x0017: "secp256r1"}

func main() {
       key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.murmur.test"},
              DNSNames: []string{"api.murmur.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
       der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
       leaf, _ := x509.ParseCertificate(der)
       pool := x509.NewCertPool()
       pool.AddCert(leaf)
       cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
       srvCfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}

       ln, _ := net.Listen("tcp", "127.0.0.1:0")
       srvSide := make(chan *countConn, 1)
       go func() {
              for {
                     raw, err := ln.Accept()
                     if err != nil {
                            return
                     }
                     cc := &countConn{Conn: raw}
                     go func() {
                            s := tls.Server(cc, srvCfg)
                            s.Handshake()
                            s.Write([]byte("ok"))
                            srvSide <- cc
                            s.Close()
                     }()
              }
       }()

       run := func(name string, curves []tls.CurveID) {
              var times []time.Duration
              var cBytes, sBytes, chello int
              var group uint16
              for i := 0; i < 200; i++ {
                     raw, _ := net.Dial("tcp", ln.Addr().String())
                     cc := &countConn{Conn: raw}
                     c := tls.Client(cc, &tls.Config{ServerName: "api.murmur.test", RootCAs: pool, MinVersion: tls.VersionTLS13, CurvePreferences: curves})
                     t0 := time.Now()
                     if err := c.Handshake(); err != nil {
                            panic(err)
                     }
                     times = append(times, time.Since(t0))
                     buf := make([]byte, 2)
                     c.Read(buf)
                     s := <-srvSide
                     if i == 0 {
                            cBytes, sBytes = cc.written, s.written
                            chello = 5 + int(binary.BigEndian.Uint16(cc.first[3:5]))
                            group = serverHelloGroup(s.first)
                     }
                     c.Close()
              }
              sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
              fmt.Printf("  %-26s %-15s %9d B %8d B %8d B   %6.0f µs\n", name, groupName[group], chello, cBytes, sBytes,
                     float64(times[len(times)/2].Microseconds()))
       }
       fmt.Printf("  %-26s %-15s %11s %10s %10s   %9s\n", "client", "server chose", "ClientHello", "client→srv", "srv→client", "median hs")
       run("classical (X25519 only)", []tls.CurveID{tls.X25519})
       run("Go 1.24 default (hybrid)", nil)
       run("hybrid only", []tls.CurveID{tls.X25519MLKEM768})
}
