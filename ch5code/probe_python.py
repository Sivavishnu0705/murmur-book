# Listing 5.7 — Probe the same cases with Python's ssl module (OpenSSL
# underneath).
import socket, ssl, sys
CASES = ["good", "expired", "not-yet-valid", "wrong-host", "wrong-eku",
         "missing-intermediate", "wildcard-multi-label", "long-lived",
         "ca-false-intermediate", "self-signed"]
# CERT_REQUIRED + hostname check
ctx = ssl.create_default_context(cafile=sys.argv[1] + "/root.pem")
for i, case in enumerate(CASES):
    try:
        with socket.create_connection(("127.0.0.1", 8441 + i), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname="api.murmur.test"):
                result = "ACCEPT"
    except ssl.SSLCertVerificationError as e:
        result = "REJECT  " + e.verify_message
    print(f"{case:22} | {result}")
