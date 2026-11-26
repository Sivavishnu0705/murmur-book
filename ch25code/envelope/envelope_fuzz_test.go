// envelope_fuzz_test.go
// Listing 25.2 — Go: fuzz test for Murmur's envelope parser (go test -fuzz).
package envelope

import (
       "bytes"
       "testing"
)

func seeds(f *testing.F) {
       f.Add((&Envelope{Type: 1, Recipient: "bob/1", Header: []byte("hdr"), Body: []byte("ciphertext")}).Encode())
       f.Add((&Envelope{Type: 3, Recipient: "x", Header: nil, Body: nil}).Encode())
       f.Add([]byte("MR"))
}

// Properties checked for EVERY input: no panic (implicit), and if accepted, the input is the
// canonical encoding of what was parsed (round trip), and limits hold.
func FuzzParse(f *testing.F) {
       seeds(f)
       f.Fuzz(func(t *testing.T, b []byte) {
              e, err := Parse(b)
              if err != nil {
                     return
              }
              if len(e.Body) > MaxBody || e.Recipient == "" {
                     t.Fatalf("limits violated: %d-byte body, recipient %q", len(e.Body), e.Recipient)
              }
              if !bytes.Equal(e.Encode(), b) {
                     t.Fatalf("non-canonical input accepted: % x", b)
              }
       })
}

func FuzzParseV0(f *testing.F) {
       seeds(f)
       f.Fuzz(func(t *testing.T, b []byte) { ParseV0(b) }) // any panic is a finding
}

// Differential check: the two parsers must agree on every input both accept.
func FuzzDifferential(f *testing.F) {
       seeds(f)
       f.Fuzz(func(t *testing.T, b []byte) {
              defer func() { recover() }() // V0's panics are FuzzParseV0's job
              e1, err1 := Parse(b)
              e2, err2 := ParseV0(b)
              if err1 == nil && err2 == nil && (e1.Recipient != e2.Recipient || !bytes.Equal(e1.Body, e2.Body)) {
                     t.Fatalf("parsers disagree on % x", b)
              }
              if err1 != nil && err2 == nil && len(b) < 64 {
                     t.Fatalf("V0 accepts what Parse rejects: % x", b)
              }
       })
}
