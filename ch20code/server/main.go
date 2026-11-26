// main.go
// Listing 20.5 — Go: lab driver — the ghost device attack against an unsigned, server-maintained
// device list, then signed device lists, rollback protection and change notifications.
package main

import (
       "crypto/ed25519"
       "crypto/rand"
       "fmt"
)

func dev(id, name string) DeviceEntry {
       var k [32]byte
       rand.Read(k[:])
       return DeviceEntry{ID: id, IdentityKey: k, Name: name, AddedAt: 1764000000}
}

func names(ds []DeviceEntry) []string {
       var out []string
       for _, d := range ds {
              out = append(out, d.Name)
       }
       return out
}

func main() {
       aikPub, aikPriv, _ := ed25519.GenerateKey(rand.Reader) // Bob's account identity key
       srv := NewServer()
       srv.aiks["bob"] = aikPub
       phone, laptop := dev("bob/1", "Bob's Pixel"), dev("bob/2", "Bob's laptop")
       v1 := &DeviceList{Account: "bob", Version: 1, Devices: []DeviceEntry{phone, laptop}}
       v1.Sign(aikPriv)
       fmt.Println("── Bob's devices publish signed list v1 ──")
       fmt.Printf("  upload v1: %v\n", srv.Upload(v1))

       alice := &Contact{AIK: aikPub, Known: map[string]DeviceEntry{}} // AIK verified by safety number
       ds, notes, err := alice.Accept(srv.Fetch("bob"))
       fmt.Printf("  Alice accepts: %v (first contact, %d notices) err=%v\n", names(ds), len(notes), err)

       fmt.Println("── Fig 20.2: malicious server adds a ghost device ──")
       ghost := dev("bob/666", "Bob's laptop") // reuses a familiar-looking name
       // (a) A design WITHOUT signed lists: the client trusts whatever the server returns.
       unsigned := srv.Fetch("bob")
       unsigned.Devices = append(unsigned.Devices, ghost)
       fmt.Printf("  unsigned design: Alice fans out to %v  ← the ghost gets every message\n", names(unsigned.Devices))
       // (b) Signed lists: the server cannot produce a valid signature over the modified list.
       _, _, err = alice.Accept(unsigned)
       fmt.Printf("  signed design:   %v → Alice keeps encrypting to the last verified list\n", err)
       // (c) The server tries to reuse v1's signature with a bumped version: the signature covers it.
       forged := srv.Fetch("bob")
       forged.Version, forged.Devices = 2, append(forged.Devices, ghost)
       _, _, err = alice.Accept(forged)
       fmt.Printf("  bumped version, old signature: %v\n", err)

       fmt.Println("── Bob legitimately adds his iPad (approved on his phone, Ch 17 pairing) ──")
       ipad := dev("bob/3", "Bob's iPad")
       v2 := &DeviceList{Account: "bob", Version: 2, Devices: []DeviceEntry{phone, laptop, ipad}}
       v2.Sign(aikPriv)
       fmt.Printf("  upload v2: %v\n", srv.Upload(v2))
       ds, notes, _ = alice.Accept(srv.Fetch("bob"))
       fmt.Printf("  Alice fans out to %v\n", names(ds))
       for _, n := range notes {
              fmt.Printf("  Alice's chat shows: %s\n", n.Text)
       }

       fmt.Println("── Bob's laptop is stolen; he removes it (v3). The server replays v2. ──")
       v3 := &DeviceList{Account: "bob", Version: 3, Devices: []DeviceEntry{phone, ipad}}
       v3.Sign(aikPriv)
       srv.Upload(v3)
       ds, notes, _ = alice.Accept(srv.Fetch("bob"))
       fmt.Printf("  Alice accepts v3: %v; notice: %s\n", names(ds), notes[0].Text)
       _, _, err = alice.Accept(v2) // server serves the old, validly signed list that includes the laptop
       fmt.Printf("  server replays v2 (still validly signed): %v\n", err)
       fmt.Printf("  server-side upload of v2 again: %v\n", srv.Upload(v2))
       _, _, err = alice.Accept(srv.Fetch("carol")) // an account that has never published a list
       fmt.Printf("  fetch for an account with no list: %v\n", err)
}
