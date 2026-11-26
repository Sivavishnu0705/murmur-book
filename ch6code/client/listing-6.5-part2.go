// Listing 6.5 (part 2) — Lab tool: a TLS 1.3 client that trusts only Murmur's root and sends one request.
package main

import (
       "crypto/tls"
       "crypto/x509"
       "flag"
       "fmt"
       "io"
       "log"
       "net/http"
       "os"
)

func main() {
       root := flag.String("root", "root.crt", "")
       url := flag.String("url", "https://murmur-api.murmur.internal:9443/", "")
       addr := flag.String("connect", "127.0.0.1:9443", "actual address to dial")
       flag.Parse()
       pool := x509.NewCertPool()
       b, err := os.ReadFile(*root)
       if err != nil {
              log.Fatal(err)
       }
       pool.AppendCertsFromPEM(b)
       tr := &http.Transport{
              TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
              DisableKeepAlives: true,
              DialTLS:           nil,
       }
       tr.DialContext = (&dialer{*addr}).dial
       resp, err := (&http.Client{Transport: tr}).Get(*url)
       if err != nil {
              log.Fatal(err)
       }
       body, _ := io.ReadAll(resp.Body)
       fmt.Printf("%s %s", resp.Status, body)
}
