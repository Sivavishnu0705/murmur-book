// main.go
// Listing 21.5 — Go: lab — "Make Murmur's server blind": compare what the relay
// and the push provider see with identified sends + content pushes vs sealed
// sender + content-free wake-ups.
package main

import (
    "crypto/ecdh"
    "crypto/ed25519"
    "crypto/rand"
    "fmt"
    "strings"
    "time"
)

func main() {
    now := time.Date(2026, 11, 25, 21, 4, 0, 0, time.UTC)
    srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
    bobIK, _ := ecdh.X25519().GenerateKey(rand.Reader) // bob/1's identity key
    aliceIK, _ := ecdh.X25519().GenerateKey(rand.Reader)

    // Bob's access key is shared with his contacts inside E2EE profile data;
    // the relay gets a hash.
    bobAccessKey := make([]byte, 32)
    rand.Read(bobAccessKey)
    relay := NewRelay()
    relay.RegisterToken("bob", DeliveryToken(bobAccessKey))
    push := &PushProvider{}

    // already E2EE (Ch 19)
    inner := []byte("<Double Ratchet ciphertext of 'meet at 9'>")

    fmt.Println("── Before: identified sends, push carries a preview ──")
    for i := 0; i < 3; i++ {
        relay.SendIdentified("alice/1", "bob/1", inner, "203.0.113.7",
            now.Add(time.Duration(i)*time.Minute))
        push.Deliver("apns:9f3c…", `{"alert":"Alice: meet at 9"}`,
            now.Add(time.Duration(i)*time.Minute))
    }
    for _, l := range relay.Log {
        fmt.Println("  relay log:", l)
    }
    fmt.Println("  push provider:", push.Seen[0])

    fmt.Println("── After: sealed sender + content-free wake-ups ──")
    relay.Log, push.Seen = nil, nil
    relay.Drain("bob/1") // Bob's device fetched the earlier messages
    // fetched daily, authenticated
    cert := IssueCert(srvPriv, "alice", "alice/1", aliceIK.PublicKey().Bytes(),
        now)
    for i := 0; i < 3; i++ {
        env := Seal(bobIK.PublicKey(), cert, inner)
        t := now.Add(time.Duration(i) * time.Minute)
        if err := relay.SendSealed("bob", "bob/1", DeliveryToken(bobAccessKey),
            env, "203.0.113.7", t); err != nil {
            panic(err)
        }
        // wake-up only; collapse id, no content
        push.Deliver("apns:9f3c…", `{"v":1}`, t)
    }
    for _, l := range relay.Log {
        fmt.Println("  relay log:", l)
    }
    fmt.Println("  push provider:", push.Seen[0])

    fmt.Println("── Bob's device unseals ──")
    for i, env := range relay.Drain("bob/1") {
        c, pt, err := Unseal(bobIK, srvPub, env, now)
        if i == 0 {
            fmt.Printf("  sender (verified cert): %s/%s  inner: %q  err=%v\n",
                c.Account, c.Device, pt, err)
        }
    }

    fmt.Println("── Abuse and forgery checks ──")
    stranger := make([]byte, 32)
    rand.Read(stranger)
    fmt.Println("  stranger without Bob's token:", relay.SendSealed("bob",
        "bob/1", DeliveryToken(stranger), Seal(bobIK.PublicKey(), cert, inner),
        "198.51.100.9", now))
    _, fakePriv, _ := ed25519.GenerateKey(rand.Reader)
    // forged cert
    fake := IssueCert(fakePriv, "carol", "carol/1", aliceIK.PublicKey().Bytes(),
        now)
    relay.SendSealed("bob", "bob/1", DeliveryToken(bobAccessKey),
        Seal(bobIK.PublicKey(), fake, inner), "203.0.113.7", now)
    _, _, err := Unseal(bobIK, srvPub, relay.Drain("bob/1")[0], now)
    fmt.Println("  contact claims to be carol with a self-made cert:", err)
    relay.SendSealed("bob", "bob/1", DeliveryToken(bobAccessKey),
        Seal(bobIK.PublicKey(), cert, inner), "203.0.113.7", now)
    _, _, err = Unseal(bobIK, srvPub, relay.Drain("bob/1")[0],
        now.Add(25*time.Hour))
    fmt.Println("  cert used after it expired:", err)
    var rl error
    for i := 0; i < 61 && rl == nil; i++ {
        rl = relay.SendSealed("bob", "bob/1", DeliveryToken(bobAccessKey),
            []byte("x"), "203.0.113.7", now)
    }
    fmt.Println("  61 sealed sends in one minute from one IP:", rl)

    fmt.Println(
        "── Padding: envelope sizes for messages of 3, 60, 150 and 400 bytes " +
        "──")
    var sizes []string
    for _, n := range []int{3, 60, 150, 400} {
        sizes = append(sizes, fmt.Sprint(len(Seal(bobIK.PublicKey(), cert,
            make([]byte, n)))))
    }
    fmt.Println("  envelope bytes:", strings.Join(sizes, ", "),
        "(cert + inner padded to 160-byte buckets)")
}
