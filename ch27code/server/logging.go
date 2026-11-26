// logging.go
// Listing 27.12 — Go: data-minimizing request logs. The logger has an ALLOWLIST of fields:
// anything else is dropped before it is written, so a careless log call cannot leak a token,
// a key, a push token, an envelope or an IP address. Device IDs are logged as a keyed hash
// that rotates daily, so logs can be correlated within a day for debugging, but not across days.
package main

import (
       "context"
       "crypto/hmac"
       "crypto/sha256"
       "encoding/hex"
       "io"
       "log/slog"
       "net/http"
       "time"
)

var logAllow = map[string]bool{
       slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true,
       "route": true, "status": true, "ms": true, "dev": true, "err_code": true,
}

func NewSafeLogger(w io.Writer) *slog.Logger {
       return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
              ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
                     if len(groups) > 0 || !logAllow[a.Key] {
                            return slog.Attr{} // dropped
                     }
                     if a.Key == slog.TimeKey { // minute precision: enough to debug, less to correlate
                            return slog.String(a.Key, a.Value.Time().UTC().Truncate(time.Minute).Format(time.RFC3339))
                     }
                     return a
              }}))
}

// Pseudonym: HMAC(daily key, device ID), 8 bytes. The daily key is discarded after 7 days,
// after which even Murmur cannot link old log lines to a device.
type Pseudonym struct{ DailyKey func(time.Time) []byte }

func (p Pseudonym) Of(device string, now time.Time) string {
       m := hmac.New(sha256.New, p.DailyKey(now))
       m.Write([]byte(device))
       return hex.EncodeToString(m.Sum(nil)[:8])
}

type statusWriter struct {
       http.ResponseWriter
       status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

// AccessLog logs the route PATTERN (never the raw path: it can contain device IDs or
// attachment IDs), status, latency and the pseudonymous device — and nothing else.
func AccessLog(log *slog.Logger, p Pseudonym, route string, next http.HandlerFunc) http.HandlerFunc {
       return func(w http.ResponseWriter, r *http.Request) {
              start := time.Now()
              sw := &statusWriter{w, 200}
              slot := &Caller{}
              next(sw, r.WithContext(context.WithValue(r.Context(), slotKey{}, slot)))
              dev := "-"
              if slot.Device != "" {
                     dev = p.Of(slot.Device, start)
              }
              log.Info("req", "route", route, "status", sw.status, "ms", time.Since(start).Milliseconds(), "dev", dev,
                     "remote_addr", r.RemoteAddr, "authorization", r.Header.Get("Authorization")) // ← both dropped
       }
}
