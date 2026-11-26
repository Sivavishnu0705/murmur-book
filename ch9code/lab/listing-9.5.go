// Listing 9.5 — Go: attestation-backed enrollment → short-lived device certificate.
package main

import (
       "crypto"
       "crypto/ecdsa"
       "crypto/rand"
       "crypto/sha256"
       "crypto/x509"
       "crypto/x509/pkix"
       "encoding/hex"
       "errors"
       "math/big"
       "net/url"
       "sync"
       "time"
)

// NonceStore issues single-use, short-lived enrollment challenges.
type NonceStore struct {
       mu   sync.Mutex
       live map[string]time.Time
}

func NewNonceStore() *NonceStore { return &NonceStore{live: map[string]time.Time{}} }

func (s *NonceStore) Issue() []byte {
       n := make([]byte, 32)
       rand.Read(n)
       s.mu.Lock()
       s.live[string(n)] = time.Now().Add(2 * time.Minute)
       s.mu.Unlock()
       return n
}

// Consume succeeds once per nonce, before expiry. Called BEFORE verifying anything else,
// so a failed attempt also burns the nonce.
func (s *NonceStore) Consume(n []byte) bool {
       s.mu.Lock()
       defer s.mu.Unlock()
       exp, ok := s.live[string(n)]
       delete(s.live, string(n))
       return ok && time.Now().Before(exp)
}

type EnrollRequest struct {
       AccountID string // from the OAuth access token (Part III), never from the request body
       Nonce     []byte
       DeviceKey *ecdsa.PublicKey // the key to certify (P-256, in StrongBox/TEE/Secure Enclave)
       PoP       []byte           // signature by DeviceKey over popMessage(nonce, account)

       AndroidChain []*x509.Certificate // Android: key attestation chain for DeviceKey

       AppAttestObject []byte // iOS: App Attest attestation object
       AppAttestKeyID  []byte //      whose clientDataHash = SHA-256(nonce || SPKI(DeviceKey))
}

func popMessage(nonce []byte, account string) []byte {
       h := sha256.Sum256(append(append([]byte("murmur/v1/enroll-pop\x00"), nonce...), account...))
       return h[:]
}

type Enroller struct {
       Nonces    *NonceStore
       Registry  *DeviceRegistry
       DevicesCA *x509.Certificate
       CAKey     crypto.Signer
       Android   AndroidPolicy
       Apple     ApplePolicy
}

func (e *Enroller) Enroll(req EnrollRequest) (*x509.Certificate, string, error) {
       if !e.Nonces.Consume(req.Nonce) {
              return nil, "", errors.New("nonce unknown, expired, or already used")
       }
       if !ecdsa.VerifyASN1(req.DeviceKey, popMessage(req.Nonce, req.AccountID), req.PoP) {
              return nil, "", errors.New("proof of possession failed")
       }
       spki, err := x509.MarshalPKIXPublicKey(req.DeviceKey)
       if err != nil {
              return nil, "", err
       }
       switch {
       case req.AndroidChain != nil:
              leaf, att, err := VerifyAndroid(req.AndroidChain, req.Nonce, e.Android)
              if err != nil {
                     return nil, "", err
              }
              attested, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
              if string(attested) != string(spki) {
                     return nil, "", errors.New("attested key is not the key to certify")
              }
              if !att.BootVerified || !att.DeviceLocked {
                     return nil, "", errors.New("device boot state not verified/locked")
              }
       case req.AppAttestObject != nil:
              cdh := sha256.Sum256(append(append([]byte{}, req.Nonce...), spki...))
              if _, err := VerifyAppAttest(req.AppAttestObject, req.AppAttestKeyID, cdh[:], e.Apple); err != nil {
                     return nil, "", err
              }
       default:
              return nil, "", errors.New("no attestation")
       }
       id := make([]byte, 8)
       rand.Read(id)
       devID := hex.EncodeToString(id)
       uri, _ := url.Parse(devicePrefix + devID)
       serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
       der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
              SerialNumber: serial, Subject: pkix.Name{CommonName: devID},
              NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(7 * 24 * time.Hour),
              KeyUsage:    x509.KeyUsageDigitalSignature,
              ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
              URIs:        []*url.URL{uri}, BasicConstraintsValid: true,
       }, e.DevicesCA, req.DeviceKey, e.CAKey)
       if err != nil {
              return nil, "", err
       }
       cert, _ := x509.ParseCertificate(der)
       e.Registry.Add(devID, req.AccountID)
       return cert, devID, nil
}
