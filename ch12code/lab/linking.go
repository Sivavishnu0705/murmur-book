// linking.go
// Listing 12.2 — Go: account resolution and linking. Accounts are keyed by (iss, sub), never
// by email. An external identity is linked to an existing account only if (a) its email is
// verified by an issuer we trust to assert that email, AND (b) the user proves control of the
// existing account in this session (signed in, recently, to the existing account).
package main

import (
       "errors"
       "fmt"
       "strings"
       "time"
)

type Identity struct{ Iss, Sub string }

type Account struct {
       ID         string
       Email      string
       Identities []Identity
}

type Accounts struct {
       byIdentity map[Identity]*Account
       byEmail    map[string]*Account
       // Issuers authoritative for an email domain (e.g. Google for gmail.com). Others' "verified"
       // email claims are treated as hints only.
       authoritative map[string]string // email domain → issuer
       n             int
}

func NewAccounts() *Accounts {
       return &Accounts{byIdentity: map[Identity]*Account{}, byEmail: map[string]*Account{},
              authoritative: map[string]string{"gmail.com": "https://accounts.google.com"}}
}

// Session is the caller's existing Murmur session, if any (Chapter 15).
type Session struct {
       AccountID string
       AuthTime  time.Time
}

var ErrLinkConfirmation = errors.New("an account with this email exists: sign in to it first to link")

// emailTrusted: verified by the provider AND, for domains with a known authoritative issuer,
// asserted by that issuer. Another IdP's "verified" claim for alice@gmail.com is only a hint.
func (a *Accounts) emailTrusted(c *IDClaims) bool {
       if !c.Verified() || c.Email == "" {
              return false
       }
       domain := strings.ToLower(c.Email[strings.LastIndex(c.Email, "@")+1:])
       if iss, ok := a.authoritative[domain]; ok && iss != c.Iss {
              return false
       }
       return true
}

func (a *Accounts) SignIn(c *IDClaims, existing *Session, now time.Time) (*Account, string, error) {
       id := Identity{c.Iss, c.Sub}
       if acct, ok := a.byIdentity[id]; ok {
              return acct, "signed in (known iss+sub)", nil // the ONLY automatic match
       }
       if other, ok := a.byEmail[c.Email]; ok && c.Email != "" {
              // Somebody already owns an account with this email. Never merge on email alone.
              if !a.emailTrusted(c) {
                     return nil, "", errors.New("email not verified by an authoritative issuer: refusing to link")
              }
              if existing == nil || existing.AccountID != other.ID || now.Sub(existing.AuthTime) > 10*time.Minute {
                     return nil, "", ErrLinkConfirmation
              }
              other.Identities = append(other.Identities, id)
              a.byIdentity[id] = other
              return other, "linked to existing account (verified email + fresh session)", nil
       }
       // New account. Only an email verified by its provider is recorded as the account's email.
       a.n++
       acct := &Account{ID: fmt.Sprintf("acct-%d", a.n), Identities: []Identity{id}}
       if a.emailTrusted(c) {
              acct.Email = c.Email
              a.byEmail[c.Email] = acct
       }
       a.byIdentity[id] = acct
       return acct, "created new account", nil
}

// CreatePasswordAccount models a pre-account: a sign-up that has NOT verified the email yet.
// It is not indexed by email until verification, so it can't capture a later social login.
func (a *Accounts) CreatePasswordAccount(email string, verified bool) *Account {
       a.n++
       acct := &Account{ID: fmt.Sprintf("acct-%d", a.n)}
       if verified {
              acct.Email = email
              a.byEmail[email] = acct
       }
       return acct
}
