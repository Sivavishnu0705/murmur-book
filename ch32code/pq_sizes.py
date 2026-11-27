# pq_sizes.py
"""Listing 32.3 — Python: what post-quantum signatures do to Murmur's messages
and certificates. Every size below is measured from real keys, signatures and
DER certificates made with the `cryptography` package (ML-KEM and ML-DSA per
FIPS 203/204), not copied from a table. Murmur's own structures are built with
the same field layout as Chapters 26-29 and serialized, then rebuilt with hybrid
(Ed25519 + ML-DSA-65) signatures."""
import datetime, os, struct, time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, mlkem

RAW = ser.Encoding.Raw, ser.PublicFormat.Raw
# Murmur's length prefix (Ch 26)
def lp(b): return struct.pack(">I", len(b)) + b

def timed(f, n=200):
    t = time.perf_counter()
    for _ in range(n): f()
    return (time.perf_counter() - t) / n * 1e6

# ── 1. Primitives
# ───────────────────────────────────────────────────────────────────────────
def sig_rows():
    out = []
    for name, gen in (("Ed25519", ed25519.Ed25519PrivateKey.generate),
        ("ECDSA P-256", lambda: ec.generate_private_key(ec.SECP256R1())),
        ("ML-DSA-44", mldsa.MLDSA44PrivateKey.generate), ("ML-DSA-65",
        mldsa.MLDSA65PrivateKey.generate),
        ("ML-DSA-87", mldsa.MLDSA87PrivateKey.generate)):
        k = gen(); m = os.urandom(200)
        if name.startswith("ECDSA"):
            pk = k.public_key().public_bytes(ser.Encoding.X962,
                ser.PublicFormat.UncompressedPoint)
            sign = lambda: k.sign(m, ec.ECDSA(hashes.SHA256())); s = sign()
            verify = lambda: k.public_key().verify(s, m,
                ec.ECDSA(hashes.SHA256()))
        else:
            pk = k.public_key().public_bytes(*RAW)
            sign = lambda: k.sign(m)
            s = sign()
            verify = lambda: k.public_key().verify(s, m)
        out.append((name, len(pk), len(s), timed(sign), timed(verify)))
    return out

print("── 1. primitives (measured) ──")
print(f"  {'KEM / DH':<14}{'public key':>11}{'ciphertext':>12}")
print(
    f"  {'X25519':<14}{32:>9} B{32:>10} B   (the 'ciphertext' is the peer's "
    f"share)")
for name, cls in (("ML-KEM-768", mlkem.MLKEM768PrivateKey), ("ML-KEM-1024",
    mlkem.MLKEM1024PrivateKey)):
    k = cls.generate(); pk = k.public_key(); ss, ct = pk.encapsulate()
    print(f"  {name:<14}{len(pk.public_bytes(*RAW)):>9} B{len(ct):>10} B")
print(f"\n  {'signature':<14}{'public key':>11}{'signature':>11}"
      f"{'sign':>11}{'verify':>11}")
SIG = {}
for name, pkl, sl, ts, tv in sig_rows():
    SIG[name] = (pkl, sl)
    print(f"  {name:<14}{pkl:>9} B{sl:>9} B{ts:>8.0f} µs{tv:>8.0f} µs")

# ── 2. Murmur's signed structures, classical vs hybrid
# ────────────────────────────────────────
ed, pq = \
    ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
def sign_classical(m): return lp(ed.sign(m))
# both must verify
def sign_hybrid(m):    return lp(ed.sign(m)) + lp(pq.sign(m))
ED_PK, PQ_PK = 32, SIG["ML-DSA-65"][0]

def device_list(n, hybrid):
    body = lp(b"murmur/v1/device-list") + lp(
        b"alice@murmur.example") + struct.pack(">Q", 7)
    # device id, identity key (+ PQ signing key), display name, capabilities
    for i in range(n):
        body += lp(os.urandom(8)) + lp(os.urandom(32)) + (lp(os.urandom(
            PQ_PK)) if hybrid else b"") \
                + lp(b"Alice's phone") + struct.pack(">HH", 0x0002, 0x0001)
    return body + (sign_hybrid(body) if hybrid else sign_classical(body))

# signed prekey + PQ last-resort prekey (ML-KEM-1024), one OPK, one PQ OPK
def prekey_bundle(hybrid):
    spk, kem = os.urandom(32), os.urandom(1568)
    sig = sign_hybrid if hybrid else sign_classical
    return lp(os.urandom(32)) + lp(spk) + sig(spk) + lp(kem) + sig(kem) + lp(
        os.urandom(32)) + lp(os.urandom(1568)) + sig(b"x" * 1568)

def sender_cert(hybrid):
    body = lp(b"murmur sender cert v1") + lp(b"alice@murmur.example") + lp(
        os.urandom(8)) + lp(os.urandom(32)) + struct.pack(">Q", 1767225600)
    return body + (sign_hybrid(body) if hybrid else sign_classical(body))

# component sum: init key, leaf HPKE key, signature key, credential, 2
# signatures
def keypackage(pq_suite):
    # MLS_128_MLKEM768X25519 + ML-DSA-65 (draft-ietf-mls-pq-ciphersuites)
    if pq_suite:
        hpke, sig_pk, sig = 1184 + 32, SIG["ML-DSA-65"][0], SIG["ML-DSA-65"][1]
    else:
        hpke, sig_pk, sig = 32, 32, 64
    # 120 B: credential, capabilities, lifetime, framing
    return 2 * hpke + sig_pk + 2 * sig + 120

print("\n── 2. Murmur structures (classical → hybrid Ed25519 + ML-DSA-65) ──")
for name, a, b in (("device list, 1 device", len(device_list(1, False)),
    len(device_list(1, True))),
    ("device list, 8 devices (max)", len(device_list(8, False)),
    len(device_list(8, True))),
    ("prekey bundle (incl. ML-KEM-1024)", len(prekey_bundle(False)),
    len(prekey_bundle(True))),
    ("sender certificate (every sealed msg)", len(sender_cert(False)),
    len(sender_cert(True))),
    ("MLS KeyPackage (PQ suite, estimate)", keypackage(False),
    keypackage(True))):
    print(f"  {name:<40}{a:>7} B → {b:>6} B   ×{b / a:.1f}")

# ── 3. X.509: what the TLS server sends (leaf + intermediate +
# CertificateVerify) ─────────────
def chain(gen, sign_hash):
    now = datetime.datetime.now(datetime.timezone.utc)
    keys = [gen() for _ in range(3)]
    certs = []
    names = ["Murmur Root", "Murmur Edge CA", "api.murmur.example"]
    for i, k in enumerate(keys):
        issuer_key = keys[max(i - 1, 0)]
        b = (x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, names[i])]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
            names[max(i - 1, 0)])]))
            .public_key(k.public_key()).serial_number(
            x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(
            days=90))
            .add_extension(x509.BasicConstraints(ca=i < 2, path_length=None),
            critical=True))
        if i == 2:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(
                names[2])]), critical=False)
        certs.append(b.sign(issuer_key, sign_hash))
    # the chain really validates
    for i in (1, 2): certs[i].verify_directly_issued_by(certs[i - 1])
    return [len(c.public_bytes(ser.Encoding.DER)) for c in certs]

print("\n── 3. TLS server authentication bytes (real DER, chain verified) ──")
print(f"  {'algorithm':<12}{'root':>8}{'interm.':>9}{'leaf':>8}"
      f"{'CertVerify':>12}{'sent':>9}   vs initcwnd (10 × 1460 B)")
for name, gen, h, cv in (("ECDSA P-256",
    lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256(), 72),
    ("ML-DSA-44", mldsa.MLDSA44PrivateKey.generate, None, SIG["ML-DSA-44"][1]),
    ("ML-DSA-65", mldsa.MLDSA65PrivateKey.generate, None, SIG["ML-DSA-65"][1])):
    r, i, l = chain(gen, h); sent = i + l + cv
    print(
        f"  {name:<12}{r:>6} B{i:>7} B{l:>6} B{cv:>10} B{sent:>7} B   "
        f"{sent / 14600:>5.0%} of the first flight")
