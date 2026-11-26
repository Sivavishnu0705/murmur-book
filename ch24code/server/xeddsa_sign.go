// xeddsa_sign.go
// XEdDSA signing for the lab CLIENT (Listing 18.1's algorithm, in Go with math/big).
// Educational and NOT constant-time; production clients use libsignal in the Rust core.
package main

import (
       "crypto/rand"
       "crypto/sha512"
       "math/big"
)

var (
       edP    = p25519
       edQ, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
       edD    = func() *big.Int {
              d := new(big.Int).ModInverse(big.NewInt(121666), edP)
              d.Mul(d, big.NewInt(-121665))
              return d.Mod(d, edP)
       }()
)

type pt struct{ x, y, z, t *big.Int }

func md(a *big.Int) *big.Int     { return a.Mod(a, edP) }
func mul(a, b *big.Int) *big.Int { return md(new(big.Int).Mul(a, b)) }

func add(p, q pt) pt {
       a := mul(new(big.Int).Sub(p.y, p.x), new(big.Int).Sub(q.y, q.x))
       b := mul(new(big.Int).Add(p.y, p.x), new(big.Int).Add(q.y, q.x))
       c := mul(mul(big.NewInt(2), edD), mul(p.t, q.t))
       d := mul(big.NewInt(2), mul(p.z, q.z))
       e, f, g, h := md(new(big.Int).Sub(b, a)), md(new(big.Int).Sub(d, c)), md(new(big.Int).Add(d, c)), md(new(big.Int).Add(b, a))
       return pt{mul(e, f), mul(g, h), mul(f, g), mul(e, h)}
}

func scalarMul(k *big.Int, p pt) pt {
       r := pt{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
       for i := k.BitLen() - 1; i >= 0; i-- {
              r = add(r, r)
              if k.Bit(i) == 1 {
                     r = add(r, p)
              }
       }
       return r
}

var edB = func() pt {
       y := mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), edP))
       // recover x from y (x even)
       yy := mul(y, y)
       xx := mul(new(big.Int).Sub(yy, big.NewInt(1)), new(big.Int).ModInverse(md(new(big.Int).Add(mul(edD, yy), big.NewInt(1))), edP))
       x := new(big.Int).Exp(xx, new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3), edP)
       if mul(x, x).Cmp(xx) != 0 {
              i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
              x = mul(x, i)
       }
       if x.Bit(0) == 1 {
              x = new(big.Int).Sub(edP, x)
       }
       return pt{x, y, big.NewInt(1), mul(x, y)}
}()

func encodePt(p pt) []byte {
       zi := new(big.Int).ModInverse(p.z, edP)
       x, y := mul(p.x, zi), mul(p.y, zi)
       out := make([]byte, 32)
       yb := y.FillBytes(make([]byte, 32))
       for i := range yb {
              out[i] = yb[31-i]
       }
       if x.Bit(0) == 1 {
              out[31] |= 0x80
       }
       return out
}

func leInt(b []byte) *big.Int {
       r := make([]byte, len(b))
       for i := range b {
              r[i] = b[len(b)-1-i]
       }
       return new(big.Int).SetBytes(r)
}

func leBytes32(n *big.Int) []byte {
       b := n.FillBytes(make([]byte, 32))
       for i, j := 0, 31; i < j; i, j = i+1, j-1 {
              b[i], b[j] = b[j], b[i]
       }
       return b
}

// SignXEdDSA signs msg with an X25519 private key (32 raw bytes).
func SignXEdDSA(xPriv []byte, msg []byte) [64]byte {
       k := append([]byte(nil), xPriv...)
       k[0] &= 248
       k[31] &= 127
       k[31] |= 64
       a := new(big.Int).Mod(leInt(k), edQ)
       A := encodePt(scalarMul(a, edB))
       if A[31]&0x80 != 0 {
              a.Sub(edQ, a)
              A = encodePt(scalarMul(a, edB))
       }
       Z := make([]byte, 64)
       rand.Read(Z)
       prefix := append([]byte{0xfe}, make([]byte, 31)...)
       for i := 1; i < 32; i++ {
              prefix[i] = 0xff
       }
       h := sha512.New()
       h.Write(prefix)
       h.Write(leBytes32(a))
       h.Write(msg)
       h.Write(Z)
       r := new(big.Int).Mod(leInt(h.Sum(nil)), edQ)
       R := encodePt(scalarMul(r, edB))
       h2 := sha512.New()
       h2.Write(R)
       h2.Write(A)
       h2.Write(msg)
       hh := new(big.Int).Mod(leInt(h2.Sum(nil)), edQ)
       s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(hh, a)), edQ)
       var sig [64]byte
       copy(sig[:32], R)
       copy(sig[32:], leBytes32(s))
       return sig
}
