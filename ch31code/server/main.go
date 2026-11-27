//go:build !lab

// main.go — the RELEASE build (Chapter 31 §31.6, the fix for T-23). Everything lab-only — the
// dev PKI, the lab attestation verifier, the dev login, the provider stand-ins, the selftest
// and the malicious-server mode — carries the `lab` build tag, so `go build .` cannot contain
// it. This book's code has no production key store, attestation verifier or identity
// provider, so the release binary refuses to start until they are wired in.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "murmur-server: release build; configure production services (see Chapter 31 §31.3)")
	os.Exit(2)
}
