// groups.go
// Listing 22.2 — Go: group membership service with admin-signed state.
// Group state is a hash chain of epochs. Each new epoch must be signed (with the AIK, Ch 20) by
// an account that was an ADMIN in the previous epoch, must increment the epoch by one, and must
// reference the previous state's hash. The server stores and relays states; it cannot create
// them. Clients verify every step from the last state they accepted, and put the current state
// hash in every group message so members detect diverging views.
package main

import (
       "crypto/ed25519"
       "crypto/sha256"
       "encoding/hex"
       "encoding/json"
       "errors"
       "fmt"
       "sort"
)

type Member struct {
       Account string
       Admin   bool
}

type GroupState struct {
       Group    string
       Epoch    uint64
       Prev     string // hex SHA-256 of the previous state's encoding ("" for epoch 0)
       Members  []Member
       SignedBy string
       Sig      []byte
}

func (s *GroupState) encode() []byte {
       ms := append([]Member(nil), s.Members...)
       sort.Slice(ms, func(i, j int) bool { return ms[i].Account < ms[j].Account })
       b, _ := json.Marshal([]any{"murmur group state v1", s.Group, s.Epoch, s.Prev, ms, s.SignedBy})
       return b
}

func (s *GroupState) Hash() string {
       h := sha256.Sum256(append(s.encode(), s.Sig...))
       return hex.EncodeToString(h[:])
}

func (s *GroupState) role(acct string) (member, admin bool) {
       for _, m := range s.Members {
              if m.Account == acct {
                     return true, m.Admin
              }
       }
       return false, false
}

// Next builds and signs the successor state on the ADMIN's device.
func Next(prev *GroupState, members []Member, admin string, key ed25519.PrivateKey) *GroupState {
       s := &GroupState{Group: prev.Group, Epoch: prev.Epoch + 1, Prev: prev.Hash(), Members: members, SignedBy: admin}
       s.Sig = ed25519.Sign(key, s.encode())
       return s
}

// Genesis: the creator signs epoch 0 and is its first admin.
func Genesis(group, creator string, members []Member, key ed25519.PrivateKey) *GroupState {
       s := &GroupState{Group: group, Epoch: 0, Members: members, SignedBy: creator}
       s.Sig = ed25519.Sign(key, s.encode())
       return s
}

// VerifyGenesis: epoch 0, no predecessor, signed by its creator, who must be an admin in it.
// Members joining later receive the whole chain and verify it from here.
func VerifyGenesis(st *GroupState, keys AIKs) error {
       if st.Epoch != 0 || st.Prev != "" {
              return ErrChain
       }
       pub, ok := keys[st.SignedBy]
       if !ok || !ed25519.Verify(pub, st.encode(), st.Sig) {
              return ErrSig
       }
       if _, admin := st.role(st.SignedBy); !admin {
              return ErrGenesisAdmin
       }
       return nil
}

var (
       ErrNotAdmin     = errors.New("signer was not an admin in the previous epoch")
       ErrGenesisAdmin = errors.New("genesis must be signed by its creator as an admin of the group")
       ErrSig          = errors.New("state signature invalid")
       ErrChain        = errors.New("state does not extend the accepted state (epoch/prev mismatch)")
)

// AIKs maps accounts to their verified account identity keys (Ch 20: safety numbers + KT).
type AIKs map[string]ed25519.PublicKey

// MemberView is one member's client.
type MemberView struct {
       Me       string
       Accepted *GroupState
       Keys     AIKs
}

// Advance verifies a chain of states from the accepted one. Every step: signature by the claimed
// signer's AIK, signer was an admin in the PREVIOUS state, epoch = prev+1, Prev = hash(prev).
func (v *MemberView) Advance(chain ...*GroupState) error {
       cur := v.Accepted
       for _, s := range chain {
              if s.Group != cur.Group || s.Epoch != cur.Epoch+1 || s.Prev != cur.Hash() {
                     return ErrChain
              }
              pub, ok := v.Keys[s.SignedBy]
              if !ok || !ed25519.Verify(pub, s.encode(), s.Sig) {
                     return ErrSig
              }
              if _, admin := cur.role(s.SignedBy); !admin {
                     return ErrNotAdmin
              }
              cur = s
       }
       v.Accepted = cur
       return nil
}

// Transcript agreement: every group message carries the sender's current state hash; a mismatch
// means the sender and receiver are in different views of the group (fork or lag).
func (v *MemberView) CheckMessage(senderStateHash string) error {
       if senderStateHash != v.Accepted.Hash() {
              return fmt.Errorf("group view mismatch: sender at %s…, me at %s…", senderStateHash[:8], v.Accepted.Hash()[:8])
       }
       return nil
}

// ---- server: stores the latest state per group; checks the chain too, but clients don't rely on it ----
type Server struct {
       states map[string]*GroupState
       keys   AIKs
}

func (s *Server) Publish(st *GroupState) error {
       cur, ok := s.states[st.Group]
       if !ok { // a new group: only a valid genesis state, signed by its creator, is accepted
              if err := VerifyGenesis(st, s.keys); err != nil {
                     return err
              }
              s.states[st.Group] = st
              return nil
       }
       v := &MemberView{Accepted: cur, Keys: s.keys}
       if err := v.Advance(st); err != nil {
              return err // e.g. two admins raced for the same epoch: the second must rebase
       }
       s.states[st.Group] = st
       return nil
}
