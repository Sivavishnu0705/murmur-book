# pq_inventory.py
"""Listing 32.1 — Python: Murmur's cryptographic inventory and post-quantum priority list.

Two parts:
  1. A hand-written INVENTORY: every place Murmur uses public-key cryptography, what it protects,
     how long that protection must last, and how long migrating it would take.
  2. A SCANNER that searches the Chapter 26-31 code for algorithm names, so the inventory can't
     silently miss a use: an algorithm found in code but absent from the inventory fails the run.

Priority follows Mosca's inequality: if x (how long the data must stay secret, or how long a
signature must stay trusted) + y (how long the migration takes) > z (years until a
cryptographically relevant quantum computer, CRQC), the item is already late. Nobody knows z,
so the report is computed for several values of z rather than one guess."""
import os, re, sys
from collections import defaultdict

YEAR = 2026
# Rows: name, algorithm(s), kind, x, y, status today [, "scan" = added after the scanner found it].
# kind: "conf" = confidentiality (harvest-now-decrypt-later applies),
#       "auth" = authentication (only a live forgery matters, at the time of use)
INVENTORY = [
    ("TLS to edge (app ↔ API)",   "X25519 → X25519MLKEM768",    "conf", 10, 1, "hybrid with iOS 26+ clients; Android to verify"),
    ("mTLS between services",     "X25519 → X25519MLKEM768",    "conf",  5, 1, "Go 1.24 default"),
    ("1:1 session setup",         "X25519 + ML-KEM-1024 (PQXDH)", "conf", 10, 0, "hybrid since Ch 18 (suite 0x0002)"),
    ("Double ratchet steps",      "X25519",                     "conf", 10, 2, "classical — PCS not PQ (SPQR-style ratchet needed)"),
    ("MLS groups",                "DHKEMX25519 (suite 0x0001)", "conf", 10, 2, "classical — needs a PQ MLS suite"),
    ("Sealed sender envelope",    "X25519 (ephemeral-static)",  "conf", 10, 1, "classical — sender identity exposed to HNDL"),
    ("Attachment keys",           "AES-256-GCM (inside E2EE)",  "conf", 10, 0, "symmetric: safe if the wrapping key exchange is"),
    ("Local database",            "AES-256 (SQLCipher)",        "conf", 10, 0, "symmetric: no change needed"),
    ("Device lists / AIK",        "Ed25519",                    "auth", 10, 3, "classical — long-lived identity keys"),
    ("Prekey and MLS credential signatures", "XEdDSA / Ed25519", "auth", 1, 3, "classical"),
    ("Sender certificates",       "Ed25519",                    "auth",  0, 1, "classical; 1-day lifetime"),
    ("Access tokens (at+jwt)",    "ES256 (ECDSA P-256)",        "auth",  0, 1, "classical; 5-min lifetime"),
    ("DPoP proofs",               "ES256 (ECDSA P-256)",        "auth",  0, 2, "classical; needs hardware PQ keys"),
    ("Device mTLS certificates",  "ECDSA P-256",                "auth",  0, 2, "classical; 7-day lifetime"),
    ("Web PKI chain at the edge", "ECDSA P-256 leaf + intermediate", "auth", 0, 4, "classical; depends on CAs and browsers"),
    ("Key attestation chains",    "ECDSA P-384 (Android), Apple", "auth", 0, 3, "platform-controlled"),
    ("Passkeys (WebAuthn)",       "ES256",                      "auth",  0, 4, "platform-controlled"),
    ("KT tree heads",             "Ed25519",                    "auth",  5, 2, "classical; old heads must stay verifiable"),
    ("App / binary signing",      "platform (APK v3, Apple)",   "auth",  5, 2, "platform-controlled (Android 17 adds ML-DSA)"),
    # Added after the first scan found RSA in code that no row described (see the lab):
    ("FCM service-account JWT",   "RS256 (RSA-2048)",           "auth",  0, 2, "provider-controlled (Google OAuth)", "scan"),
    ("Upstream IdP ID tokens",    "RS256 (RSA)",                "auth",  0, 2, "provider-controlled (OIDC JWKS)", "scan"),
]

# Algorithm families the scanner recognizes, and which inventory algorithms cover them.
FAMILIES = {
    "X25519":  r"\bx25519\b|\bcurve25519\b|DHKEMX25519",
    "Ed25519": r"\bed25519\b",
    "XEdDSA":  r"\bxeddsa\b",
    "ECDSA":   r"\becdsa\b|\bES256\b|\bP-?256\b|secp256r1",
    "RSA":     r"\bRSA\b|\brsa\.\b|PKCS1v15|\bRS256\b",
    "ML-KEM":  r"ml-?kem|mlkem",
    "ML-DSA":  r"ml-?dsa|mldsa",
    "AES-GCM": r"aes.?\d{3}.?gcm|AESGCM|\bAES\.GCM\b",
}

def scan(roots):
    hits = defaultdict(set)
    for root in roots:
        for d, _, files in os.walk(root):
            for f in files:
                if not f.endswith((".go", ".py", ".kt", ".swift", ".rs")): continue
                p = os.path.join(d, f)
                src = open(p, errors="replace").read()
                for fam, rx in FAMILIES.items():
                    if re.search(rx, src, re.I): hits[fam].add(os.path.relpath(p, os.path.dirname(root)))
    return hits

def rows():
    return [r for r in INVENTORY if not (FIRST_PASS and len(r) > 6)]

def covered(fam):
    rx = re.compile(FAMILIES[fam], re.I)
    return any(rx.search(r[1]) for r in rows())

def report(roots):
    hits = scan(roots)
    print("── 1. scanner: algorithm families in the Chapter 26–31 code ──")
    missing = []
    for fam in FAMILIES:
        n = len(hits.get(fam, ()))
        ok = covered(fam)
        note = "in inventory" if ok else ("NOT IN INVENTORY" if n else "—")
        if n and not ok: missing.append(fam)
        files = sorted(hits.get(fam, ()))
        where = f"  e.g. {files[0]}" if files and not ok else ""
        print(f"  {fam:<8} {n:>3} files   {note}{where}")
    print("\n── 2. Mosca's inequality: x (secrecy/trust years) + y (migration years) vs z ──")
    zs = (7, 10, 15)
    print(f"  {'use':<38}{'kind':<6}{'x':>3}{'y':>3}  " + "".join(f"z={z:<4}" for z in zs) + " status today")
    table = []
    for name, alg, kind, x, y, status, *_ in rows():
        symmetric = alg.startswith("AES")
        hybrid = "MLKEM" in alg.replace("-", "") and "→" not in alg
        def verdict(z):
            if symmetric or hybrid: return "ok"
            return "LATE" if x + y > z else "ok"
        v = [verdict(z) for z in zs]
        table.append((v.count("LATE"), name, kind, x, y, v, status))
    # Most LATE verdicts first; on a tie, confidentiality (exposed to HNDL today) before
    # authentication (exposed only once a CRQC exists); then alphabetically.
    for late, name, kind, x, y, v, status in sorted(table, key=lambda r: (-r[0], r[2] != "conf", r[1])):
        print(f"  {name:<38.38}{kind:<6}{x:>3}{y:>3}  " + "".join(f"{s:<6}" for s in v) + f" {status}")
    print("\n  x for 'conf' = years the data must stay secret; for 'auth' = years the key (or a")
    print("  signature it made) must stay trusted. A CRQC that arrives while it is trusted forges it.")
    print("  'ok' for hybrid and symmetric items: already safe against a CRQC.")
    if missing:
        print(f"\n  FAIL: algorithms used in code but missing from the inventory: {', '.join(missing)}")
        return 1
    print("\n  inventory complete: every algorithm family found in code is accounted for")
    return 0

FIRST_PASS = False
if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--first-pass": FIRST_PASS, args = True, args[1:]
    if FIRST_PASS:
        print("── scanner only, inventory as first written ──")
        hits = scan(args); bad = [f for f in FAMILIES if hits.get(f) and not covered(f)]
        for f in FAMILIES:
            files = sorted(hits.get(f, ()))
            print(f"  {f:<8} {len(files):>3} files   " + ("in inventory" if covered(f) else "NOT IN INVENTORY: " + ", ".join(files[:3]) + (" …" if len(files) > 3 else "") if files else "—"))
        sys.exit(1 if bad else 0)
    sys.exit(report(args))
