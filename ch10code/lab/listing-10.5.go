//go:build serve

// Listing 10.5 — Go: run the resource server against a real authorization
// server (lab).
//
//     go run -tags serve . -issuer http://localhost:8080/realms/murmur \
// -jwks http://localhost:8080/realms/murmur/protocol/openid-connect/certs \
//         -aud https://api.murmur.example -typ JWT
package main

import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"
)

func main() {
    iss := flag.String("issuer", "",
        "expected iss (exactly as the AS writes it)")
    jwksURL := flag.String("jwks", "",
        "JWKS URL (from the AS's discovery document)")
    aud := flag.String("aud", "https://api.murmur.example",
        "this resource server's audience")
    typ := flag.String("typ", "at+jwt", "comma-separated accepted typ values")
    flag.Parse()
    p := Policy{Issuer: *iss, Audience: *aud, JWKSURL: *jwksURL,
        Leeway: 60 * time.Second,
        AllowedTyp: strings.Split(*typ, ",")}
    http.Handle("/v1/messages", RequireToken(p, NewJWKS(p.JWKSURL),
        "messages:send",
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c := r.Context().Value(claimsKey{}).(*Claims)
            fmt.Fprintf(w, "accepted: sub=%s client_id=%s scope=%q\n", c.Sub,
            c.ClientID, c.Scope)
        })))
    log.Println(
        "resource server on http://127.0.0.1:9000 (lab: plain HTTP on " +
        "loopback only)")
    log.Fatal(http.ListenAndServe("127.0.0.1:9000", nil))
}
