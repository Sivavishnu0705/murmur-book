// mls.go
// Listing 27.8 — Go: MLS commit ordering. The relay is the MLS Delivery Service (Ch 23): it
// reads ONLY the cleartext framing of each MLSMessage (RFC 9420 §6: group_id, epoch,
// content_type), accepts exactly one Commit per epoch via a compare-and-swap, and fans the
// winner out to every member. Everything else in the message stays opaque.
package main

import (
       "bytes"
       "encoding/binary"
       "encoding/json"
       "errors"
       "net/http"
       "slices"
       "sync"
)

const (
       wirePublic, wirePrivate, wireWelcome = 1, 2, 3
       ctApplication, ctProposal, ctCommit  = 1, 2, 3
)

type MLSHeader struct {
       WireFormat  uint16
       GroupID     []byte
       Epoch       uint64
       ContentType uint8
}

var errMLS = errors.New("malformed MLS framing")

// readVarint implements RFC 9420 §2.1.2: 2-bit length prefix, MINIMAL encoding required.
func readVarint(r *bytes.Reader) (uint64, error) {
       b0, err := r.ReadByte()
       if err != nil {
              return 0, errMLS
       }
       n := 1 << (b0 >> 6)
       if n == 8 {
              return 0, errMLS // prefix 0b11 is invalid
       }
       v := uint64(b0 & 0x3f)
       for i := 1; i < n; i++ {
              b, err := r.ReadByte()
              if err != nil {
                     return 0, errMLS
              }
              v = v<<8 | uint64(b)
       }
       if (n == 2 && v < 64) || (n == 4 && v < 16384) {
              return 0, errMLS // non-minimal: two encodings of one length is a parser-differential risk
       }
       return v, nil
}

func readOpaque(r *bytes.Reader) ([]byte, error) {
       n, err := readVarint(r)
       if err != nil || n > uint64(r.Len()) {
              return nil, errMLS
       }
       b := make([]byte, n)
       r.Read(b)
       return b, nil
}

// ParseMLSHeader reads the framing of a PublicMessage or PrivateMessage.
func ParseMLSHeader(msg []byte) (*MLSHeader, error) {
       r := bytes.NewReader(msg)
       var version uint16
       h := &MLSHeader{}
       if binary.Read(r, binary.BigEndian, &version) != nil || version != 1 { // mls10
              return nil, errMLS
       }
       if binary.Read(r, binary.BigEndian, &h.WireFormat) != nil {
              return nil, errMLS
       }
       if h.WireFormat != wirePublic && h.WireFormat != wirePrivate {
              return nil, errMLS
       }
       var err error
       if h.GroupID, err = readOpaque(r); err != nil || len(h.GroupID) == 0 {
              return nil, errMLS
       }
       if binary.Read(r, binary.BigEndian, &h.Epoch) != nil {
              return nil, errMLS
       }
       if h.WireFormat == wirePublic { // FramedContent: sender, authenticated_data, then content_type
              st, err := r.ReadByte()
              if err != nil {
                     return nil, errMLS
              }
              switch st {
              case 1, 2: // member(leaf_index) / external(sender_index): uint32
                     if _, err := r.Seek(4, 1); err != nil || r.Len() == 0 {
                            return nil, errMLS
                     }
              case 3, 4: // new_member_proposal / new_member_commit: no index
              default:
                     return nil, errMLS
              }
              if _, err := readOpaque(r); err != nil { // authenticated_data
                     return nil, errMLS
              }
       }
       if h.ContentType, err = r.ReadByte(); err != nil || h.ContentType < ctApplication || h.ContentType > ctCommit {
              return nil, errMLS
       }
       return h, nil
}

type DS struct {
       Devices *Registry // routing skips revoked devices until a member commits their removal
       Groups  GroupStore
       Queues  QueueStore
       Wake    func(device string)
       mu      sync.Mutex
       members map[string][]string // group → member devices for the CURRENT epoch (routing only)
}

func NewDS(reg *Registry, g GroupStore, q QueueStore, wake func(string)) *DS {
       return &DS{Devices: reg, Groups: g, Queues: q, Wake: wake, members: map[string][]string{}}
}

// POST /v1/groups/commit  (scope messages:send)
// Body: {message: MLSMessage, members: device IDs of the NEW epoch, welcome?: bytes for joiners}
// The member list is routing data supplied by the committer. Members verify the real roster
// from the Commit itself (Ch 23); a lying committer can only misroute, never add a reader.
func (ds *DS) Commit(w http.ResponseWriter, r *http.Request) {
       c := CallerFrom(r)
       var q struct {
              Message, Welcome []byte
              Members, Joiners []string
       }
       if !readJSON(w, r, 2<<20, &q) {
              return
       }
       h, err := ParseMLSHeader(q.Message)
       if err != nil || h.ContentType != ctCommit || len(q.Members) == 0 || len(q.Members) > 1000 {
              writeErr(w, 400, "MALFORMED", false)
              return
       }
       gid := string(h.GroupID)
       ds.mu.Lock()
       defer ds.mu.Unlock()
       cur := ds.members[gid]
       if cur != nil && !slices.Contains(cur, c.Device) {
              writeErr(w, 404, "NOT_FOUND", false) // only members may commit
              return
       }
       switch err := ds.Groups.AdvanceEpoch(r.Context(), h.GroupID, h.Epoch, q.Message); {
       case errors.Is(err, ErrStaleEpoch):
              epoch, _ := ds.Groups.Epoch(r.Context(), h.GroupID)
              w.Header().Set("Content-Type", "application/json")
              w.WriteHeader(409) // lost the race: fetch the winning commit, merge it, rebase, retry
              json.NewEncoder(w).Encode(map[string]any{"code": "STALE_EPOCH", "retryable": true, "epoch": epoch})
              return
       case err != nil:
              writeErr(w, 503, "UNAVAILABLE", true)
              return
       }
       // Fan-out in a fixed order: existing members (incl. removed ones, so they learn they are out)
       // get the Commit; joiners get the Welcome. In production this joins AdvanceEpoch's transaction.
       for _, m := range union(cur, q.Members) {
              if m != c.Device && !slices.Contains(q.Joiners, m) {
                     ds.enqueue(r, m, q.Message)
              }
       }
       for _, j := range q.Joiners {
              ds.enqueue(r, j, q.Welcome)
       }
       ds.members[gid] = append([]string(nil), q.Members...)
       w.WriteHeader(202)
}

// POST /v1/groups/message  (scope messages:send) — application messages for the current epoch
// (or the one before, for messages already in flight when a commit landed).
func (ds *DS) Message(w http.ResponseWriter, r *http.Request) {
       c := CallerFrom(r)
       var q struct{ Message []byte }
       if !readJSON(w, r, maxEnvelope, &q) {
              return
       }
       h, err := ParseMLSHeader(q.Message)
       if err != nil || h.ContentType != ctApplication || h.WireFormat != wirePrivate {
              writeErr(w, 400, "MALFORMED", false) // application data is never sent as PublicMessage
              return
       }
       ds.mu.Lock()
       defer ds.mu.Unlock()
       members := ds.members[string(h.GroupID)]
       epoch, _ := ds.Groups.Epoch(r.Context(), h.GroupID)
       if !slices.Contains(members, c.Device) {
              writeErr(w, 404, "NOT_FOUND", false)
              return
       }
       if h.Epoch > epoch || h.Epoch+1 < epoch {
              w.Header().Set("Content-Type", "application/json")
              w.WriteHeader(409)
              json.NewEncoder(w).Encode(map[string]any{"code": "STALE_EPOCH", "retryable": true, "epoch": epoch})
              return
       }
       for _, m := range members {
              if m != c.Device {
                     ds.enqueue(r, m, q.Message)
              }
       }
       w.WriteHeader(202)
}

func (ds *DS) enqueue(r *http.Request, device string, body []byte) {
       if d, ok := ds.Devices.Get(device); !ok || !d.RevokedAt.IsZero() {
              return
       }
       guid := make([]byte, 16)
       randRead(guid)
       if ds.Queues.Enqueue(r.Context(), device, guid, body, envelopeTTL) == nil {
              ds.Wake(device)
       }
}

func union(a, b []string) []string {
       out := append([]string(nil), a...)
       for _, x := range b {
              if !slices.Contains(out, x) {
                     out = append(out, x)
              }
       }
       return out
}
