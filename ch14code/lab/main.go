// main.go
// Listing 14.5 — Go: lab driver. A simulated passkey provider and client (the
// OS/browser part that writes the origin and enforces RP ID rules) against
// Listing 14.4's verifier.
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "net/url"
    "strings"
    "time"
)

type passkey struct {
    rpID, user string
    id         []byte
    k          *ecdsa.PrivateKey
    count      uint32 // device-bound keys count; synced passkeys stay 0
    synced     bool
}

// provider = Google Password Manager / iCloud Keychain / a security key.
type provider struct{ keys []*passkey }

// client = the OS or browser. It, not the calling page/app, decides the origin,
// and refuses an RP ID the caller is not entitled to (web: registrable-domain
// suffix; app: verified association).
type client struct {
    origin     string
    // RP IDs this app is linked to (assetlinks.json / AASA webcredentials)
    associated map[string]bool
}

func (c client) checkRP(rpID string) error {
    if c.associated != nil {
        if !c.associated[rpID] {
            return fmt.Errorf("SecurityError: app not associated with RP ID %q",
                rpID)
        }
        return nil
    }
    u, _ := url.Parse(c.origin)
    if h := u.Hostname(); h != rpID && !strings.HasSuffix(h, "."+rpID) {
        return fmt.Errorf("SecurityError: RP ID %q is not valid for origin %s",
            rpID, c.origin)
    }
    return nil
}

func cdj(typ, challenge, origin string) []byte {
    b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge,
        "origin": origin, "crossOrigin": false})
    return b
}

func authData(rpID string, flags byte, count uint32, attested []byte) []byte {
    h := sha256.Sum256([]byte(rpID))
    ad := append(h[:], flags)
    ad = binary.BigEndian.AppendUint32(ad, count)
    return append(ad, attested...)
}

func (p *provider) create(c client, rpID, user, challenge string,
    synced bool) (*passkey, []byte, []byte, error) {
    if err := c.checkRP(rpID); err != nil {
        return nil, nil, nil, err
    }
    k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    id := make([]byte, 16)
    rand.Read(id)
    pk := &passkey{rpID: rpID, user: user, id: id, k: k, synced: synced}
    flags := byte(flagUP | flagUV | flagAT)
    if synced {
        flags |= flagBE | flagBS
    } else {
        pk.count = 1
    }
    cose := cborEncode(map[any]any{1: 2, 3: -7, -1: 1,
        -2: k.X.FillBytes(make([]byte, 32)), -3: k.Y.FillBytes(make([]byte,
        32))})
    // AAGUID zero ("none")
    att := append(make([]byte, 16), byte(len(id)>>8), byte(len(id)))
    att = append(append(att, id...), cose...)
    ao := cborEncode(map[any]any{"fmt": "none", "attStmt": map[any]any{},
        "authData": authData(rpID, flags, pk.count, att)})
    p.keys = append(p.keys, pk)
    return pk, cdj("webauthn.create", challenge, c.origin), ao, nil
}

type assertion struct{ id, cd, ad, sig []byte }

func (p *provider) get(c client, rpID, challenge string, uv bool) (*assertion,
    error) {
    if err := c.checkRP(rpID); err != nil {
        return nil, err
    }
    var pk *passkey
    for _, k := range p.keys {
        if k.rpID == rpID {
            pk = k
        }
    }
    if pk == nil {
        return nil,
            errors.New(
            "no passkey for this site (the user's passkeys are for " +
            "murmur.example)")
    }
    flags := byte(flagUP)
    if uv {
        flags |= flagUV
    }
    if pk.synced {
        flags |= flagBE | flagBS
    } else {
        pk.count++
    }
    ad := authData(rpID, flags, pk.count, nil)
    cd := cdj("webauthn.get", challenge, c.origin)
    h := sha256.Sum256(cd)
    d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
    sig, _ := ecdsa.SignASN1(rand.Reader, pk.k, d[:])
    return &assertion{pk.id, cd, ad, sig}, nil
}

func main() {
    now := time.Now()
    // SHA-256 of signing cert
    apk := "android:apk-key-hash:FyNmShqTj3BpxuPLPqLQtB_4f8DeNAw7Rk3wFt8n0Hw"
    rp := RP{ID: "murmur.example", Origins: map[string]bool{
        // murmur-auth's web login (browser / Custom Tab)
        "https://auth.murmur.example": true,
        // iOS app (origin derived from the associated domain)
        "https://murmur.example":      true,
        // Android app, identified by its signing certificate
        apk:                           true,
    }}
    chs := NewChallenges()
    newCh := func(kind, user string) string {
        b := make([]byte, 32)
        rand.Read(b)
        c := b64.EncodeToString(b)
        chs.Put(c, kind, user, now.Add(5*time.Minute))
        return c
    }
    store := map[string]*Credential{}
    android := client{origin: apk,
        associated: map[string]bool{"murmur.example": true}}
    iphone := client{origin: "https://murmur.example",
        associated: map[string]bool{"murmur.example": true}}
    gpm, icloud, key := &provider{}, &provider{}, &provider{}

    register := func(label string, p *provider, c client, synced bool) {
        _, cd, ao, err := p.create(c, "murmur.example", "alice",
            newCh("webauthn.create", "alice"), synced)
        if err == nil {
            var cr *Credential
            if cr, err = rp.FinishRegistration(cd, ao, chs, now); err == nil {
                store[string(cr.ID)] = cr
                fmt.Printf("  %-52s registered  BE=%v BS=%v counter=%d\n",
                    label, cr.BE, cr.BS, cr.SignCount)
                return
            }
        }
        fmt.Printf("  %-52s FAIL  %v\n", label, err)
    }
    login := func(label string, p *provider, c client, rpID string, uv,
        requireUV bool) *assertion {
        a, err := p.get(c, rpID, newCh("webauthn.get", ""), uv)
        if err != nil {
            fmt.Printf("  %-52s FAIL  %v\n", label, err)
            return nil
        }
        show(label, rp, store, a, chs, requireUV, now)
        return a
    }

    fmt.Println("── Registration (Fig 14.2) ──")
    register("Android app, Google Password Manager (synced)", gpm, android,
        true)
    register("iOS app, iCloud Keychain (synced)", icloud, iphone, true)
    register("security key (device-bound)", key,
        client{origin: "https://auth.murmur.example"}, false)

    fmt.Println("── Authentication (Fig 14.3) ──")
    a := login("Android app", gpm, android, "murmur.example", true, true)
    login("iOS app", icloud, iphone, "murmur.example", true, true)
    login("browser at https://auth.murmur.example, security key", key,
        client{origin: "https://auth.murmur.example"}, "murmur.example", true,
        true)

    fmt.Println("── Attacks ──")
    phish := client{origin: "https://murmur-login.example"}
    login("phishing page asks for rpId murmur.example", gpm, phish,
        "murmur.example", true, true)
    login("phishing page asks for its own rpId", gpm, phish,
        "murmur-login.example", true, true)
    fake := client{origin: "android:apk-key-hash:ATTACKER-SIGNING-CERT",
        associated: map[string]bool{}}
    login("look-alike app (not in assetlinks.json)", gpm, fake,
        "murmur.example", true, true)
    broken := client{origin: "https://murmur-login.example",
        associated: map[string]bool{"murmur.example": true}}
    login("relay via a BROKEN client that ignores RP rules", gpm, broken,
        "murmur.example", true, true)
    show("replay of the Android assertion", rp, store, a, chs, true, now)
    t, _ := gpm.get(android, "murmur.example", newCh("webauthn.get", ""), false)
    t.ad[32] |= flagUV
    show("UV flag set after signing (tampered authData)", rp, store, t, chs,
        true, now)
    login("step-up with UP only (no biometric/PIN)", gpm, android,
        "murmur.example", false, true)
    key.keys[0].count-- // a cloned security key replays an old counter value
    login("cloned device-bound key (counter goes back)", key,
        client{origin: "https://auth.murmur.example"}, "murmur.example", true,
        true)
}

func show(label string, rp RP, store map[string]*Credential, a *assertion,
    chs *Challenges, requireUV bool, now time.Time) {
    // The client returns {credential id, clientDataJSON, authenticatorData,
    // signature}; the challenge inside clientDataJSON is the one the server
    // issued for this ceremony.
    r, err := rp.FinishLogin(store, a.id, a.cd, a.ad, a.sig, chs, requireUV,
        now)
    switch {
    case err != nil:
        fmt.Printf("  %-52s REJECT  %v\n", label, err)
    case r.CloneWarning:
        fmt.Printf(
            "  %-52s FLAG    signature ok, counter did not increase → " +
            "possible clone\n", label)
    default:
        fmt.Printf("  %-52s OK      user=%s UV=%v counter=%d\n", label,
            r.Cred.User, r.UV, r.Cred.SignCount)
    }
}
