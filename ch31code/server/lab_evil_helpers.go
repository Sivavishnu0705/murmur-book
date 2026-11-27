//go:build lab

// lab_evil_helpers.go — internals the malicious-server mode (Listing 31.4) needs: inventing a
// device without attestation, and sending a push whose alert carries attacker-chosen text.
// Lab build only.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// inventDevice adds a device to the registry the way a compromised server could: no nonce,
// no proof of possession, no attestation.
func (r *Registry) inventDevice(account, jkt string, now time.Time) string {
	id := make([]byte, 8)
	rand.Read(id)
	dev := &Device{ID: "dev-" + hex.EncodeToString(id), Account: account, Platform: "android",
		Jkt: jkt, Enrolled: now}
	r.mu.Lock()
	r.devices[dev.ID] = dev
	r.mu.Unlock()
	return dev.ID
}

// pushText sends an APNs alert with the given body (an honest gateway only ever sends the
// fixed placeholder). The device's NSE must not display it (red-team finding RT-6).
func (g *Gateway) pushText(device, body string) {
	d, ok := g.Devices.Get(device)
	if !ok || d.PushToken == "" || d.Platform != "ios" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"aps": map[string]any{
		"alert": map[string]string{"title": "Murmur", "body": body}, "mutable-content": 1}, "v": 1})
	req, _ := http.NewRequest("POST", g.APNs.Base+"/3/device/"+url.PathEscape(d.PushToken), bytes.NewReader(payload))
	req.Header.Set("authorization", "bearer "+g.APNs.providerToken(false))
	req.Header.Set("apns-topic", g.APNs.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-collapse-id", collapseID)
	if resp, err := g.APNs.HTTP.Do(req); err == nil {
		resp.Body.Close()
	}
}
