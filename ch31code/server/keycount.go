// keycount.go — GET /v1/keys/count (added in Chapter 28, §28.5). The device's prekey job asks
// how many one-time prekeys of each kind the server still holds, then tops up below the
// low-water marks. Scope prekeys:write: only the device itself needs its own counts.
package main

import (
	"encoding/json"
	"net/http"
)

func (d *Directory) CountKeys(w http.ResponseWriter, r *http.Request) {
	dev := CallerFrom(r).Device
	ec, err1 := d.Keys.CountOneTime(r.Context(), dev, "ec")
	pq, err2 := d.Keys.CountOneTime(r.Context(), dev, "pq")
	if err1 != nil || err2 != nil {
		writeErr(w, 503, "UNAVAILABLE", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"one_time": ec, "pq_one_time": pq})
}
