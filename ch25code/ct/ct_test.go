// ct_test.go
// Listing 25.5 — Go: measuring a timing side channel. An early-exit comparison of a MAC tag
// takes longer the more leading bytes match; crypto/subtle.ConstantTimeCompare does not.
package ct

import (
       "crypto/subtle"
       "fmt"
       "testing"
)

//go:noinline
func naiveEqual(a, b []byte) bool { // ⚠️ INSECURE: returns at the first differing byte
       if len(a) != len(b) {
              return false
       }
       for i := range a {
              if a[i] != b[i] {
                     return false
              }
       }
       return true
}

func TestTiming(t *testing.T) {
       secret := make([]byte, 1024) // a long tag makes the effect easy to see without noise
       for i := range secret {
              secret[i] = byte(i)
       }
       for _, pos := range []int{0, 256, 512, 1023} {
              guess := append([]byte(nil), secret...)
              guess[pos] ^= 1 // first difference at `pos`
              n := testing.Benchmark(func(b *testing.B) {
                     for i := 0; i < b.N; i++ {
                            naiveEqual(secret, guess)
                     }
              })
              c := testing.Benchmark(func(b *testing.B) {
                     for i := 0; i < b.N; i++ {
                            subtle.ConstantTimeCompare(secret, guess)
                     }
              })
              fmt.Printf("  first mismatch at byte %4d:  naive %7.1f ns   ConstantTimeCompare %7.1f ns\n",
                     pos, float64(n.T.Nanoseconds())/float64(n.N), float64(c.T.Nanoseconds())/float64(c.N))
       }
}
