// evil.go
//go:build lab

// Listing 31.4 — Go: the lab's MALICIOUS SERVER MODE (build tag `lab` only;
// never in a release binary — the release gate of Listing 31.3 checks the
// symbols). A loopback-only control port lets the red-team scripts make the
// server lie in the ways Chapter 3's threat model says a compromised server
// can: forge bundles, invent devices, roll back device lists, replace an AIK,
// replay envelopes, inject push text and substitute KeyPackages. Each attack is
// applied by WRAPPING the honest handler, so the production handlers are
// byte-for-byte unchanged.
package main

import (
    "bytes"
    "encoding/json"
    "io"
    "net"
    "net/http"
    "sync"
    "time"
)

type Evil struct {
    mu        sync.Mutex
    bundles   map[string][]byte   // device → forged bundle JSON, served once
    // account → device-list response to serve instead of the current one
    listServe map[string][]byte
    // account → every device-list response ever served honestly
    history   map[string][][]byte
    // device → substituted KeyPackage, served once
    kps       map[string][]byte
    // account → accept any fan-out for it (no DEVICE_MISMATCH check)
    bypass    map[string]bool
    // device → envelopes kept back for revoked devices (for "the thief")
    captured  map[string][][]byte
    Log       []string
}

func NewEvil() *Evil {
    return &Evil{bundles: map[string][]byte{}, listServe: map[string][]byte{},
        history: map[string][][]byte{},
        kps: map[string][]byte{}, bypass: map[string]bool{},
        captured: map[string][][]byte{}}
}

func (e *Evil) note(s string) { e.mu.Lock(); e.Log = append(e.Log, s);
    e.mu.Unlock() }

type captureWriter struct {
    http.ResponseWriter
    buf    bytes.Buffer
    status int
}

func (c *captureWriter) WriteHeader(s int) { c.status = s;
    c.ResponseWriter.WriteHeader(s) }
func (c *captureWriter) Write(b []byte) (int, error) {
    c.buf.Write(b)
    return c.ResponseWriter.Write(b)
}

func (e *Evil) WrapBundle(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        e.mu.Lock()
        forged, ok := e.bundles[r.PathValue("device")]
        delete(e.bundles, r.PathValue("device"))
        e.mu.Unlock()
        if ok {
            w.Header().Set("Content-Type", "application/json")
            w.Write(forged)
            return
        }
        next(w, r)
    }
}

func (e *Evil) WrapDeviceList(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        acct := r.PathValue("account")
        e.mu.Lock()
        fake, ok := e.listServe[acct]
        e.mu.Unlock()
        if ok {
            w.Header().Set("Content-Type", "application/json")
            w.Write(fake)
            return
        }
        cw := &captureWriter{ResponseWriter: w, status: 200}
        next(cw, r)
        // remember every honest version, for the rollback attack
        if cw.status == 200 {
            e.mu.Lock()
            h := e.history[acct]
            if len(h) == 0 || !bytes.Equal(h[len(h)-1], cw.buf.Bytes()) {
                e.history[acct] = append(h, append([]byte(nil),
                    cw.buf.Bytes()...))
            }
            e.mu.Unlock()
        }
    }
}

func (e *Evil) WrapKeyPackage(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        e.mu.Lock()
        kp, ok := e.kps[r.PathValue("device")]
        delete(e.kps, r.PathValue("device"))
        e.mu.Unlock()
        if ok {
            json.NewEncoder(w).Encode(map[string]any{"key_package": kp,
                "last_resort": false, "remaining": 0})
            return
        }
        next(w, r)
    }
}

// WrapSend: with bypass on for the recipient account, accept whatever device
// set the sender chose and keep every envelope — including those for revoked
// devices, which an honest relay would refuse — so the lab can hand them to
// whoever holds that device's stolen keys.
func (e *Evil) WrapSend(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        r.Body = io.NopCloser(bytes.NewReader(body))
        var q sendReq
        json.Unmarshal(body, &q)
        e.mu.Lock()
        on := e.bypass[q.RecipientAccount]
        if on {
            for _, env := range q.Envelopes {
                e.captured[env.Device] = append(e.captured[env.Device],
                    env.Body)
            }
        }
        e.mu.Unlock()
        if on {
            w.WriteHeader(202)
            return
        }
        next(w, r)
    }
}

// Serve the control port on 127.0.0.1 only. mint/enroll/enqueue/push are
// closures over the lab server's internals (registry, token key, queues, APNs
// client).
func (e *Evil) Serve(enroll func(account, jkt string, ik []byte) (string,
    string), enqueue func(device string, body []byte),
    push func(device, alertBody string), setAIK func(account string,
    aik []byte)) int {
    mux := http.NewServeMux()
    read := func(r *http.Request, v any) { b, _ := io.ReadAll(r.Body);
        json.Unmarshal(b, v) }
    mux.HandleFunc("POST /evil/bundle", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Device string
            Bundle json.RawMessage
        }
        read(r, &q)
        e.mu.Lock()
        e.bundles[q.Device] = q.Bundle
        e.mu.Unlock()
        e.note("forged bundle armed for " + q.Device)
    })
    mux.HandleFunc("POST /evil/rollback", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Account string
            Index   int // which historic version to serve (0 = oldest)
        }
        read(r, &q)
        e.mu.Lock()
        e.listServe[q.Account] = e.history[q.Account][q.Index]
        e.mu.Unlock()
        e.note("device list of " + q.Account + " rolled back")
    })
    mux.HandleFunc("POST /evil/devicelist", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Account string
            // {"encoded":…,"signature":…} signed by an attacker AIK
            List    json.RawMessage
            AIK     []byte
        }
        read(r, &q)
        e.mu.Lock()
        e.listServe[q.Account] = q.List
        e.mu.Unlock()
        setAIK(q.Account, q.AIK)
        e.note("AIK and device list of " + q.Account + " replaced")
    })
    mux.HandleFunc("POST /evil/clear", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct{ Account string }
        read(r, &q)
        e.mu.Lock()
        delete(e.listServe, q.Account)
        e.mu.Unlock()
    })
    mux.HandleFunc("POST /evil/device", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Account, Jkt string
            IK           []byte
        }
        read(r, &q)
        id, tok := enroll(q.Account, q.Jkt, q.IK)
        e.note("invented device " + id + " for " + q.Account)
        json.NewEncoder(w).Encode(map[string]string{"device_id": id,
            "token": tok})
    })
    mux.HandleFunc("POST /evil/replay", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Device string
            Body   []byte
        }
        read(r, &q)
        enqueue(q.Device, q.Body)
        e.note("replayed an envelope to " + q.Device)
    })
    mux.HandleFunc("POST /evil/push", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct{ Device, Text string }
        read(r, &q)
        push(q.Device, q.Text)
        e.note("injected push text to " + q.Device)
    })
    mux.HandleFunc("POST /evil/bypass", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Account string
            On      bool
        }
        read(r, &q)
        e.mu.Lock()
        e.bypass[q.Account] = q.On
        e.mu.Unlock()
    })
    mux.HandleFunc("GET /evil/captured/{device}", func(w http.ResponseWriter,
        r *http.Request) {
        e.mu.Lock()
        defer e.mu.Unlock()
        json.NewEncoder(w).Encode(map[string][][]byte{
        "envelopes": e.captured[r.PathValue("device")]})
    })
    mux.HandleFunc("GET /evil/log", func(w http.ResponseWriter,
        r *http.Request) {
        e.mu.Lock()
        defer e.mu.Unlock()
        json.NewEncoder(w).Encode(e.Log)
    })
    mux.HandleFunc("POST /evil/keypackage", func(w http.ResponseWriter,
        r *http.Request) {
        var q struct {
            Device string
            KP     []byte
        }
        read(r, &q)
        e.mu.Lock()
        e.kps[q.Device] = q.KP
        e.mu.Unlock()
        e.note("substituted KeyPackage armed for " + q.Device)
    })
    ln, _ := net.Listen("tcp", "127.0.0.1:0")
    go (&http.Server{Handler: mux,
        ReadHeaderTimeout: 5 * time.Second}).Serve(ln)
    return ln.Addr().(*net.TCPAddr).Port
}
