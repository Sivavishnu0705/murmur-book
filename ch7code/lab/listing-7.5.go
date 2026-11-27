// Listing 7.5 — Go: exporting keying material bound to this TLS connection.
package main

import "crypto/tls"

// TLSExporterBinding returns the RFC 9266 "tls-exporter" channel binding value:
// 32 bytes from the TLS exporter with label "EXPORTER-Channel-Binding" and no
// context. Client and server compute the same value; any other connection gets
// a different one.
func TLSExporterBinding(cs tls.ConnectionState) ([]byte, error) {
    return cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
}

// MurmurExporter derives an application-specific value with its own label and
// context, e.g. to bind a device-enrollment signature to the connection
// (Chapters 9 and 24).
func MurmurExporter(cs tls.ConnectionState, context []byte) ([]byte, error) {
    return cs.ExportKeyingMaterial("EXPORTER-murmur-enrollment-v1", context, 32)
}
