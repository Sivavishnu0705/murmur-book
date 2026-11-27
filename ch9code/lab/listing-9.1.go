// Listing 9.1 — Go: an mTLS server that requires device certificates, extracts
// the SPIFFE-style device ID from the URI SAN, and authorizes per device.
package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "net/http"
    "strings"
    "sync"
)

const devicePrefix = "spiffe://murmur.internal/device/"

type DeviceRegistry struct {
    mu      sync.Mutex
    owner   map[string]string // deviceID → accountID
    revoked map[string]bool
}

func NewRegistry() *DeviceRegistry {
    return &DeviceRegistry{owner: map[string]string{},
        revoked: map[string]bool{}}
}
func (r *DeviceRegistry) Add(dev, acct string) { r.mu.Lock();
    r.owner[dev] = acct; r.mu.Unlock() }
func (r *DeviceRegistry) Revoke(dev string)    { r.mu.Lock();
    r.revoked[dev] = true; r.mu.Unlock() }
func (r *DeviceRegistry) Active(dev string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    _, ok := r.owner[dev]
    return ok && !r.revoked[dev]
}

// deviceID returns the device identity from a VALIDATED chain, or an error if
// the client certificate is not a Murmur device certificate (e.g. a service
// certificate, which also carries clientAuth but was issued by a different
// intermediate).
func deviceID(chain []*x509.Certificate, devicesCA *x509.Certificate) (string,
    error) {
    if len(chain) < 2 || !bytes.Equal(chain[1].Raw, devicesCA.Raw) {
        return "",
            errors.New("client certificate not issued by Murmur Devices CA")
    }
    leaf := chain[0]
    if len(leaf.URIs) != 1 || !strings.HasPrefix(leaf.URIs[0].String(),
        devicePrefix) {
        return "", errors.New("client certificate has no device URI SAN")
    }
    return strings.TrimPrefix(leaf.URIs[0].String(), devicePrefix), nil
}

func MTLSConfig(serverCert tls.Certificate, root, devicesCA *x509.Certificate,
    reg *DeviceRegistry) *tls.Config {
    clientRoots := x509.NewCertPool()
    // only Murmur's private root — never the system store
    clientRoots.AddCert(root)
    return &tls.Config{
        MinVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{serverCert},
        // chain, validity, clientAuth EKU
        ClientAuth:   tls.RequireAndVerifyClientCert,
        ClientCAs:    clientRoots,
        // Identity and revocation checks at handshake time, on every
        // connection:
        VerifyConnection: func(cs tls.ConnectionState) error {
            if len(cs.VerifiedChains) == 0 {
                return errors.New("no verified client chain")
            }
            id, err := deviceID(cs.VerifiedChains[0], devicesCA)
            if err != nil {
                return err
            }
            if !reg.Active(id) {
                // registry beats CRLs (Ch 5)
                return fmt.Errorf("device %s unknown or revoked", id)
            }
            return nil
        },
    }
}

type ctxKey struct{}

// WithDevice puts the authenticated device ID into the request context.
func WithDevice(devicesCA *x509.Certificate, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
            http.Error(w, "client certificate required",
            http.StatusUnauthorized)
            return
        }
        id, err := deviceID(r.TLS.VerifiedChains[0], devicesCA)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{},
            id)))
    })
}

// KeysHandler: GET/PUT /v1/devices/{id}/keys — a device may act only on itself.
func KeysHandler(w http.ResponseWriter, r *http.Request) {
    caller := r.Context().Value(ctxKey{}).(string)
    target := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/devices/"),
        "/keys")
    if target != caller {
        http.Error(w, "forbidden: not your device", http.StatusForbidden)
        return
    }
    fmt.Fprintf(w, "keys for device %s\n", caller)
}
