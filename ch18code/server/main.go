// main.go
// Listing 18.6 — Go: lab driver. (1) An independent Go X3DH computes the Python
// test vectors; (2) concurrent fetches never hand out the same OPK; (3) rate
// limits stop bundle exhaustion.
package main

import (
    "crypto/ecdh"
    "crypto/hkdf"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "sync"
    "time"
)

type kp struct{ Priv, Pub string }

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func dh(priv, pub string) []byte {
    k, _ := ecdh.X25519().NewPrivateKey(mustHex(priv))
    p, _ := ecdh.X25519().NewPublicKey(mustHex(pub))
    out, _ := k.ECDH(p)
    return out
}

func x3dhSK(info string, dhs ...[]byte) string {
    km := make([]byte, 32)
    for i := range km {
        km[i] = 0xff
    }
    for _, d := range dhs {
        km = append(km, d...)
    }
    sk, _ := hkdf.Key(sha256.New, km, make([]byte, 32), info, 32)
    return hex.EncodeToString(sk)
}

func main() {
    var v struct {
        Info    string
        SpkSig  string `json:"spk_sig"`
        Keys    map[string]kp
        With    map[string]string `json:"with_opk"`
        Without map[string]string `json:"without_opk"`
    }
    raw, err := os.ReadFile("../x3dh_vectors.json")
    if err != nil {
        panic(err)
    }
    json.Unmarshal(raw, &v)
    k := v.Keys
    fmt.Println("── Python test vectors, recomputed independently in Go ──")
    var ikB, spkB [32]byte
    var sig [64]byte
    copy(ikB[:], mustHex(k["ik_b"].Pub))
    copy(spkB[:], mustHex(k["spk_b"].Pub))
    copy(sig[:], mustHex(v.SpkSig))
    fmt.Printf(
        "  XEdDSA SPK signature verifies (Go ed25519 + u→y conversion): %v\n",
        VerifyXEdDSA(ikB, append([]byte{0x05}, spkB[:]...), sig))
    // Alice's side: DH(IK_A, SPK_B), DH(EK_A, IK_B), DH(EK_A, SPK_B) [,
    // DH(EK_A, OPK_B)]
    d1 := dh(k["ik_a"].Priv, k["spk_b"].Pub)
    d2 := dh(k["ek_a"].Priv, k["ik_b"].Pub)
    d3 := dh(k["ek_a"].Priv, k["spk_b"].Pub)
    d4 := dh(k["ek_a"].Priv, k["opk_b"].Pub)
    fmt.Printf("  with OPK:    SK matches Python: %v\n", x3dhSK(v.Info, d1, d2,
        d3, d4) == v.With["sk"])
    fmt.Printf("  without OPK: SK matches Python: %v\n", x3dhSK(v.Info, d1, d2,
        d3) == v.Without["sk"])
    // Bob's side computes the same DHs from the other end:
    e1 := dh(k["spk_b"].Priv, k["ik_a"].Pub)
    fmt.Printf("  Bob's DH(SPK_B, IK_A) equals Alice's DH1: %v\n",
        hex.EncodeToString(e1) == v.With["dh1"])

    fmt.Println(
        "── Prekey directory: 50 concurrent fetches, 20 one-time prekeys ──")
    now := time.Now()
    dir := NewDirectory(1000)
    notified := 0
    dir.Notify = func(string) { notified++ }
    opks := make([]OneTimePrekey, 20)
    for i := range opks {
        opks[i] = OneTimePrekey{ID: uint32(i + 1)}
    }
    fmt.Printf("  publish with a forged SPK signature: %v\n",
        dir.Publish("bob/1", ikB, SignedPrekey{ID: 1, Pub: spkB}, opks))
    fmt.Printf("  publish with the real signature:     %v\n",
        dir.Publish("bob/1", ikB, SignedPrekey{ID: 1, Pub: spkB, Sig: sig},
        opks))
    var mu sync.Mutex
    seen := map[uint32]int{}
    without := 0
    var wg sync.WaitGroup
    for i := 0; i < 50; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            b, err := dir.Fetch(fmt.Sprintf("user%d", i), "bob/1", now)
            if err != nil {
                return
            }
            mu.Lock()
            if b.OPK == nil {
                without++
            } else {
                seen[b.OPK.ID]++
            }
            mu.Unlock()
        }(i)
    }
    wg.Wait()
    dups := 0
    for _, n := range seen {
        if n > 1 {
            dups++
        }
    }
    fmt.Printf(
        "  distinct OPKs handed out: %d, duplicates: %d, bundles without " +
        "OPK: %d, low-water pushes: %d\n",
        len(seen), dups, without, notified)

    fmt.Println(
        "── Bundle exhaustion attack: one account requests Carol's bundle in " +
        "a loop ──")
    // 10 bundle fetches per minute per requester (and per pair)
    dir2 := NewDirectory(10)
    many := make([]OneTimePrekey, 100)
    for i := range many {
        many[i] = OneTimePrekey{ID: uint32(i + 1)}
    }
    dir2.Publish("carol/1", ikB, SignedPrekey{ID: 1, Pub: spkB, Sig: sig}, many)
    served, limited := 0, 0
    for i := 0; i < 1000; i++ {
        if _, err := dir2.Fetch("mallory", "carol/1",
            now.Add(time.Duration(i)*time.Second/10)); err != nil {
            limited++
        } else {
            served++
        }
    }
    fmt.Printf(
        "  1,000 requests over 100 s: served %d, rate-limited %d, Carol's " +
        "OPKs left: %d of 100\n",
        served, limited, dir2.Remaining("carol/1"))
}
