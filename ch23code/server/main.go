// main.go
// Listing 23.3 — Go: lab driver for the delivery service: concurrent commits,
// stale application messages, removal fan-out, and KeyPackage claims.
package main

import (
    "fmt"
    "time"
)

func main() {
    ds := NewDS()
    ds.Create("g", "alice")
    ds.Submit(Envelope{Group: "g", Epoch: 0, Kind: Commit, Sender: "alice"},
        []string{"bob", "carol", "dave"}, nil)
    fmt.Println("── Two members commit concurrently in epoch 1 ──")
    fmt.Println("  bob's commit:  ", ds.Submit(Envelope{Group: "g", Epoch: 1,
        Kind: Commit, Sender: "bob"}, nil, nil))
    fmt.Println("  carol's commit:", ds.Submit(Envelope{Group: "g", Epoch: 1,
        Kind: Commit, Sender: "carol"}, nil, nil))
    q := ds.Fetch("g", "dave")
    fmt.Printf(
        "  dave's queue: %d handshake message(s), from %s → every member " +
        "sees the same order\n", len(q), q[len(q)-1].Sender)

    fmt.Println("── Application messages across an epoch change ──")
    fmt.Println("  carol sends in epoch 1 (sent before she saw bob's commit):",
        ds.Submit(Envelope{Group: "g", Epoch: 1, Kind: Application,
        Sender: "carol"}, nil, nil))
    ds.Submit(Envelope{Group: "g", Epoch: 2, Kind: Commit, Sender: "alice"},
        nil, nil)
    fmt.Println("  dave sends with epoch 1 keys after two more epochs:     ",
        ds.Submit(Envelope{Group: "g", Epoch: 1, Kind: Application,
        Sender: "dave"}, nil, nil))
    fmt.Println("  someone claims epoch 9:                                 ",
        ds.Submit(Envelope{Group: "g", Epoch: 9, Kind: Application,
        Sender: "dave"}, nil, nil))

    fmt.Println("── Remove dave ──")
    ds.Fetch("g", "dave")
    ds.Submit(Envelope{Group: "g", Epoch: 3, Kind: Commit, Sender: "alice"},
        nil, []string{"dave"})
    ds.Submit(Envelope{Group: "g", Epoch: 4, Kind: Application, Sender: "bob"},
        nil, nil)
    fmt.Printf(
        "  dave receives: %d message (the Commit removing him); the next " +
        "application message is not routed to him\n", len(ds.Fetch("g",
        "dave")))

    fmt.Println("  submit to a group that doesn't exist:",
        ds.Submit(Envelope{Group: "nope", Epoch: 0, Kind: Commit, Sender: "x"},
        nil, nil),
        "| fetch from it:", len(ds.Fetch("nope", "x")), "messages")

    fmt.Println("── KeyPackage directory ──")
    now := time.Now()
    dir := NewDirectory()
    dir.Upload("erin/1",
        KeyPackage{ID: "kp1", NotAfter: now.Add(-time.Hour)}, // expired
        KeyPackage{ID: "kp2", NotAfter: now.Add(30 * 24 * time.Hour)},
        KeyPackage{ID: "kp3", NotAfter: now.Add(30 * 24 * time.Hour)},
        KeyPackage{ID: "last", LastResort: true,
        NotAfter: now.Add(90 * 24 * time.Hour)})
    for i := 0; i < 4; i++ {
        kp, err := dir.Claim("erin/1", now)
        fmt.Printf("  claim %d: %s last-resort=%v err=%v\n", i+1, kp.ID,
            kp.LastResort, err)
    }
    time.Sleep(10 * time.Millisecond)
}
