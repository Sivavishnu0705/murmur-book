// account.go — murmur-auth's account types used by Listing 14.3 (passkeys.go).
// Not printed in the book: Account implements webauthn.User, AccountDB is the storage
// interface the login path needs, and MemDB is a small in-memory AccountDB for tests.
package passkeys

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrConfirmFromAnotherDevice is returned when a device-bound credential's signature
// counter goes backwards (a possible clone, §14.5). The login is refused and the user
// is asked to confirm from another signed-in device.
var ErrConfirmFromAnotherDevice = errors.New("passkey counter regression: confirm from another device")

// ErrUnknownUser is returned when no account has the given user handle.
var ErrUnknownUser = errors.New("unknown user handle")

// Account is one murmur-auth account. UserHandle is a random 32-byte value chosen at
// account creation: never an email or phone number, because authenticators store it.
type Account struct {
	ID          string
	UserHandle  []byte
	Name        string // login name shown in the passkey picker
	DisplayName string
	Credentials []webauthn.Credential

	mu sync.Mutex
}

// webauthn.User
func (a *Account) WebAuthnID() []byte          { return a.UserHandle }
func (a *Account) WebAuthnName() string        { return a.Name }
func (a *Account) WebAuthnDisplayName() string { return a.DisplayName }
func (a *Account) WebAuthnCredentials() []webauthn.Credential {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]webauthn.Credential(nil), a.Credentials...)
}

// SaveCredential stores a newly registered credential. A credential ID that is already
// registered is refused, so one authenticator cannot be bound to two accounts' records.
func (a *Account) SaveCredential(c *webauthn.Credential) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, have := range a.Credentials {
		if bytes.Equal(have.ID, c.ID) {
			return errors.New("credential already registered")
		}
	}
	a.Credentials = append(a.Credentials, *c)
	return nil
}

// AccountDB is the storage murmur-auth's login path needs.
type AccountDB interface {
	ByUserHandle(handle []byte) (*Account, error)
	UpdateCredential(a *Account, c *webauthn.Credential) error
	RecordSecurityEvent(a *Account, event string)
}

// SecurityEvent is one entry in an account's security log (shown to the user, Ch 15).
type SecurityEvent struct {
	AccountID string
	Event     string
	At        time.Time
}

// MemDB is an in-memory AccountDB, for tests and the lab.
type MemDB struct {
	mu       sync.Mutex
	accounts map[string]*Account // keyed by string(UserHandle)
	Events   []SecurityEvent
}

func NewMemDB() *MemDB { return &MemDB{accounts: map[string]*Account{}} }

func (db *MemDB) Add(a *Account) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.accounts[string(a.UserHandle)] = a
}

func (db *MemDB) ByUserHandle(handle []byte) (*Account, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if a, ok := db.accounts[string(handle)]; ok {
		return a, nil
	}
	return nil, ErrUnknownUser
}

// UpdateCredential persists the new signature counter, flags and last-use data after a
// successful login. It replaces the stored credential with the same ID.
func (db *MemDB) UpdateCredential(a *Account, c *webauthn.Credential) error {
	if a == nil {
		return ErrUnknownUser
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.Credentials {
		if bytes.Equal(a.Credentials[i].ID, c.ID) {
			a.Credentials[i] = *c
			return nil
		}
	}
	return errors.New("credential not registered to this account")
}

func (db *MemDB) RecordSecurityEvent(a *Account, event string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	id := ""
	if a != nil {
		id = a.ID
	}
	db.Events = append(db.Events, SecurityEvent{AccountID: id, Event: event, At: time.Now()})
}
