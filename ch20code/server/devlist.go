// devlist.go
// Listing 20.1 — Go: device list service with signed device-list records.
// Each account has an Account Identity Key (AIK, Ed25519) held only by the user's linked
// devices. The device list (device ID + device identity key for X3DH) is signed by the AIK,
// with a strictly increasing version. The server stores and serves the latest record; it
// cannot create one. Clients verify the signature against the AIK they trust (safety number,
// key transparency) and refuse versions older than the newest they have seen.
package main

import (
       "bytes"
       "crypto/ed25519"
       "encoding/binary"
       "errors"
       "fmt"
       "sort"
       "sync"
)

type DeviceEntry struct {
       ID          string
       IdentityKey [32]byte // the device's X25519 identity key (Ch 18)
       Name        string   // shown to contacts: "Bob's iPad"
       AddedAt     int64
}

type DeviceList struct {
       Account string
       Version uint64
       Devices []DeviceEntry
       Sig     []byte // Ed25519 by the account's AIK over Encode()
}

// Encode is unambiguous: a domain label, length-prefixed fields, devices sorted by ID.
func (l *DeviceList) Encode() []byte {
       var b bytes.Buffer
       put := func(s []byte) { binary.Write(&b, binary.BigEndian, uint32(len(s))); b.Write(s) }
       put([]byte("murmur device list v1"))
       put([]byte(l.Account))
       binary.Write(&b, binary.BigEndian, l.Version)
       ds := append([]DeviceEntry(nil), l.Devices...)
       sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
       binary.Write(&b, binary.BigEndian, uint32(len(ds)))
       for _, d := range ds {
              put([]byte(d.ID))
              b.Write(d.IdentityKey[:])
              put([]byte(d.Name))
              binary.Write(&b, binary.BigEndian, d.AddedAt)
       }
       return b.Bytes()
}

// Sign runs on one of the user's devices (the one approving the change), never on the server.
func (l *DeviceList) Sign(aik ed25519.PrivateKey) { l.Sig = ed25519.Sign(aik, l.Encode()) }

// ---- server ----

type Server struct {
       mu    sync.Mutex
       lists map[string]*DeviceList
       aiks  map[string]ed25519.PublicKey // also published to key transparency (§20.5)
}

func NewServer() *Server {
       return &Server{lists: map[string]*DeviceList{}, aiks: map[string]ed25519.PublicKey{}}
}

var (
       ErrSignature = errors.New("device list signature invalid")
       ErrRollback  = errors.New("device list version not newer than current")
       ErrNoList    = errors.New("no device list published for this account")
)

// Upload accepts a new signed list from the account's own device. The server checks the
// signature and version too, so it never stores garbage, but CLIENTS must not rely on that.
func (s *Server) Upload(l *DeviceList) error {
       s.mu.Lock()
       defer s.mu.Unlock()
       if !ed25519.Verify(s.aiks[l.Account], l.Encode(), l.Sig) {
              return ErrSignature
       }
       if cur, ok := s.lists[l.Account]; ok && l.Version <= cur.Version {
              return ErrRollback
       }
       s.lists[l.Account] = l
       return nil
}

// Fetch returns a copy of the account's current list, or nil if none has been published yet.
func (s *Server) Fetch(account string) *DeviceList {
       s.mu.Lock()
       defer s.mu.Unlock()
       cur, ok := s.lists[account]
       if !ok {
              return nil
       }
       c := *cur
       c.Devices = append([]DeviceEntry(nil), c.Devices...)
       return &c
}

// ---- client ----

type Contact struct {
       AIK         ed25519.PublicKey // trusted via safety number / KT; changes are a separate event (§20.6)
       SeenVersion uint64
       Known       map[string]DeviceEntry
}

type Notice struct{ Text string }

// Accept verifies a fetched list and returns the devices to encrypt to, plus user-visible
// notices for every device added or removed since the last accepted list.
func (c *Contact) Accept(l *DeviceList) ([]DeviceEntry, []Notice, error) {
       if l == nil {
              return nil, nil, ErrNoList
       }
       if !ed25519.Verify(c.AIK, l.Encode(), l.Sig) {
              return nil, nil, ErrSignature
       }
       if l.Version < c.SeenVersion {
              return nil, nil, fmt.Errorf("%w (got v%d, have seen v%d)", ErrRollback, l.Version, c.SeenVersion)
       }
       var notices []Notice
       first := c.SeenVersion == 0 // first contact: record silently (trust comes from the AIK check)
       now := map[string]DeviceEntry{}
       for _, d := range l.Devices {
              now[d.ID] = d
              if old, ok := c.Known[d.ID]; first {
                     continue
              } else if !ok {
                     notices = append(notices, Notice{fmt.Sprintf("%s added a new device: %q", l.Account, d.Name)})
              } else if old.IdentityKey != d.IdentityKey {
                     notices = append(notices, Notice{fmt.Sprintf("%s's device %q has a new key", l.Account, d.Name)})
              }
       }
       for id, d := range c.Known {
              if _, ok := now[id]; !ok {
                     notices = append(notices, Notice{fmt.Sprintf("%s removed device %q", l.Account, d.Name)})
              }
       }
       c.SeenVersion, c.Known = l.Version, now
       return l.Devices, notices, nil
}
