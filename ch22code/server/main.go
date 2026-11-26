// main.go
// Listing 22.3 — Go: lab driver for admin-signed group membership.
package main

import (
       "crypto/ed25519"
       "crypto/rand"
       "fmt"
)

func main() {
       keys, priv := AIKs{}, map[string]ed25519.PrivateKey{}
       for _, a := range []string{"alice", "bob", "carol", "dave", "eve"} {
              pub, pk, _ := ed25519.GenerateKey(rand.Reader)
              keys[a], priv[a] = pub, pk
       }
       g0 := Genesis("book-club", "alice", []Member{{"alice", true}, {"bob", true}, {"carol", false}, {"dave", false}}, priv["alice"])
       srv := &Server{states: map[string]*GroupState{}, keys: keys}
       fmt.Println("── Genesis ──")
       fakeGen := Genesis("book-club", "carol", []Member{{"carol", false}, {"dave", false}}, priv["carol"])
       fmt.Println("  genesis whose creator is not an admin:", srv.Publish(fakeGen))
       fmt.Println("  alice's genesis (alice and bob admins):", srv.Publish(g0))
       carol := &MemberView{Me: "carol", Accepted: g0, Keys: keys}
       dave := &MemberView{Me: "dave", Accepted: g0, Keys: keys}

       fmt.Println("── Legitimate change: admin bob adds eve ──")
       g1 := Next(g0, []Member{{"alice", true}, {"bob", true}, {"carol", false}, {"dave", false}, {"eve", false}}, "bob", priv["bob"])
       fmt.Println("  server publish:", srv.Publish(g1), " carol advances:", carol.Advance(g1), " dave advances:", dave.Advance(g1))

       fmt.Println("── Malicious server adds a member it controls ──")
       ghost := *g1
       ghost.Epoch, ghost.Prev = 2, g1.Hash()
       ghost.Members = append(append([]Member(nil), g1.Members...), Member{"server-ghost", false})
       fmt.Println("  re-using bob's signature:", carol.Advance(&ghost))
       srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
       keys2 := AIKs{"murmur-server": srvPub}
       for k, v := range keys {
              keys2[k] = v
       }
       carol.Keys = keys2 // even if the server had a key Carol knew...
       signed := Next(g1, ghost.Members, "murmur-server", srvPriv)
       fmt.Println("  signed by the server's own key:", carol.Advance(signed))
       carol.Keys = keys

       fmt.Println("── Non-admin carol tries to remove bob ──")
       bad := Next(g1, []Member{{"alice", true}, {"carol", false}, {"dave", false}, {"eve", false}}, "carol", priv["carol"])
       fmt.Println("  dave checks it:", dave.Advance(bad))

       fmt.Println("── Race: alice and bob both create epoch 2 ──")
       a2 := Next(g1, []Member{{"alice", true}, {"bob", true}, {"carol", false}, {"dave", false}}, "alice", priv["alice"])            // removes eve
       b2 := Next(g1, []Member{{"alice", true}, {"bob", true}, {"carol", false}, {"dave", false}, {"eve", true}}, "bob", priv["bob"]) // promotes eve
       fmt.Println("  server accepts alice's:", srv.Publish(a2), "| then bob's:", srv.Publish(b2), "→ bob must rebase on alice's epoch 2")

       fmt.Println("── Fork: a server shows carol and dave different (validly signed) epoch-2 states ──")
       carol.Advance(a2)
       dave.Advance(b2) // dave was shown bob's conflicting state
       msgFromCarol := carol.Accepted.Hash()
       fmt.Println("  dave receives a group message from carol:", dave.CheckMessage(msgFromCarol))
       fmt.Println("  → clients stop, re-fetch, and surface 'group state conflict' instead of encrypting to two different member sets")
}
