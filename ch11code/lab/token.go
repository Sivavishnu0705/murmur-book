// token.go
// Listing 11.1 — Go: authorization server side of PKCE (RFC 7636) plus refresh
// rotation. S256 only, exact redirect_uri match, single-use codes (reuse
// revokes the token family), and refresh-token reuse detection.
package main

import (
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "sync"
    "time"
)

var b64 = base64.RawURLEncoding

type authCode struct {
    clientID, redirectURI, challenge, sub string
    expires                               time.Time
    used                                  bool
    family                                string // tokens issued from this code
}

type refreshToken struct {
    family, clientID, sub string
    used                  bool
}

type AuthServer struct {
    mu          sync.Mutex
    // client_id → exact registered redirect URIs
    clients     map[string][]string
    codes       map[string]*authCode
    refresh     map[string]*refreshToken
    revoked     map[string]bool // token families
    RequirePKCE bool            // false only to demonstrate the attack (lab)
}

func NewAuthServer() *AuthServer {
    return &AuthServer{clients: map[string][]string{},
        codes: map[string]*authCode{},
        refresh: map[string]*refreshToken{}, revoked: map[string]bool{},
        RequirePKCE: true}
}

func random() string { b := make([]byte, 32); rand.Read(b);
    return b64.EncodeToString(b) }

var (
    ErrInvalidRequest = errors.New("invalid_request")
    ErrInvalidGrant   = errors.New("invalid_grant")
)

// Authorize runs after the user has authenticated in the browser. It validates
// the request and returns the code that the AS will put in the redirect.
func (s *AuthServer) Authorize(clientID, redirectURI, sub, challenge,
    method string) (string, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    // exact string match, no prefixes/wildcards
    if !contains(s.clients[clientID], redirectURI) {
        return "", ErrInvalidRequest
    }
    if s.RequirePKCE {
        // "plain" (or absent) would let an interceptor reuse the challenge
        if method != "S256" {
            return "", ErrInvalidRequest
        }
        if len(challenge) != 43 { // base64url(SHA-256) without padding
            return "", ErrInvalidRequest
        }
    }
    code := random()
    s.codes[code] = &authCode{clientID: clientID, redirectURI: redirectURI,
        challenge: challenge,
        sub: sub, expires: time.Now().Add(60 * time.Second)}
    return code, nil
}

type Tokens struct{ Access, Refresh string }

// ExchangeCode is the token endpoint for grant_type=authorization_code.
func (s *AuthServer) ExchangeCode(code, clientID, redirectURI,
    verifier string) (*Tokens, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    c, ok := s.codes[code]
    if !ok || time.Now().After(c.expires) {
        return nil, ErrInvalidGrant
    }
    // second redemption: interception likely → revoke what the first one got
    if c.used {
        if c.family != "" {
            s.revoked[c.family] = true
        }
        return nil, ErrInvalidGrant
    }
    c.used = true // burn the code on ANY redemption attempt, successful or not
    if c.clientID != clientID || c.redirectURI != redirectURI {
        return nil, ErrInvalidGrant
    }
    if s.RequirePKCE {
        // RFC 7636: verifier is 43–128 chars;
        // BASE64URL(SHA256(ASCII(verifier))) == challenge
        if len(verifier) < 43 || len(verifier) > 128 {
            return nil, ErrInvalidGrant
        }
        sum := sha256.Sum256([]byte(verifier))
        if subtle.ConstantTimeCompare([]byte(b64.EncodeToString(sum[:])),
            []byte(c.challenge)) != 1 {
            return nil, ErrInvalidGrant
        }
    }
    c.family = random()
    return s.issue(c.family, clientID, c.sub), nil
}

// Refresh is the token endpoint for grant_type=refresh_token, with rotation +
// reuse detection.
func (s *AuthServer) Refresh(rt, clientID string) (*Tokens, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    r, ok := s.refresh[rt]
    if !ok || r.clientID != clientID || s.revoked[r.family] {
        return nil, ErrInvalidGrant
    }
    // an old refresh token came back: someone has a copy → kill the whole
    // family
    if r.used {
        s.revoked[r.family] = true
        return nil, ErrInvalidGrant
    }
    r.used = true
    return s.issue(r.family, clientID, r.sub), nil
}

func (s *AuthServer) issue(family, clientID, sub string) *Tokens {
    rt := random()
    s.refresh[rt] = &refreshToken{family: family, clientID: clientID, sub: sub}
    return &Tokens{Access: "at-" + random()[:12], Refresh: rt}
}

func (s *AuthServer) FamilyRevoked(rt string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    r, ok := s.refresh[rt]
    return ok && s.revoked[r.family]
}

func contains(list []string, v string) bool {
    for _, x := range list {
        if x == v {
            return true
        }
    }
    return false
}
