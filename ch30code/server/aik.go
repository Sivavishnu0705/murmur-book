// aik.go — Chapter 29's additions to the key directory (described in §29.1 and §29.6, not
// printed): the AIK lookup a client uses when a device list no longer verifies under the AIK
// it knows, the replacement rule's check, and the device set the relay requires.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"slices"
)

// GET /v1/aik/{account}  (scope messages:send). Production adds a key transparency proof
// (Ch 20 §20.5): a client must not take a new AIK on the server's word alone.
func (d *Directory) GetAIK(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	aik, ok := d.aiks[r.PathValue("account")]
	d.mu.Unlock()
	if !ok {
		writeErr(w, 404, "NOT_FOUND", false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]ed25519.PublicKey{"aik": aik})
}

// listed returns the device IDs in the account's current signed list. Caller holds d.mu.
func (d *Directory) listed(account string) []string {
	l, ok := d.lists[account]
	if !ok {
		return nil
	}
	_, _, devs, err := parseDeviceList(l[:len(l)-64])
	if err != nil {
		return nil
	}
	var out []string
	for id := range devs {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// ListedDevices is the relay's required device set (Chapter 29): devices in the account's
// AIK-signed list. A device that enrolled but that the AIK never approved receives nothing,
// and senders are never asked to encrypt to it. Relay.activeDevices then drops revoked ones.
func (d *Directory) ListedDevices(account string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.listed(account)
}

// aikHeldByAnother: is some other active device in the current list? Then the old AIK still
// exists on a device the user controls, and replacing it is refused. Caller holds d.mu.
func (d *Directory) aikHeldByAnother(account, caller string) bool {
	for _, id := range d.listed(account) {
		if dev, ok := d.Devices.Get(id); ok && id != caller && dev.RevokedAt.IsZero() {
			return true
		}
	}
	return false
}
