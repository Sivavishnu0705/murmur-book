# safety.py
"""Listing 20.2 — Python: safety number computation (Signal-style numeric
fingerprint): 5,200 iterations of SHA-512 over (version ‖ identity key ‖ stable
identifier), first 30 bytes
→ six 5-digit groups per party, the two halves ordered by identifier. Checked
against a published libsignal test vector."""
import hashlib

ITERATIONS = 5200
VERSION = (0).to_bytes(2, "big")

def fingerprint(identity_key: bytes, stable_id: bytes,
    iterations=ITERATIONS) -> bytes:
    h = VERSION + identity_key + stable_id
    # slow on purpose: costs a brute-forcer ~5,200× per guess
    for _ in range(iterations):
        h = hashlib.sha512(h + identity_key).digest()
    return h

def digits(fp: bytes) -> str:
    # six chunks of 5 bytes → big-endian integer mod 100000 → 5 digits each = 30
    # digits
    return "".join(
        f"{int.from_bytes(fp[i:i+5], 'big') % 100000:05d}" for i in range(0, 30,
        5))

def safety_number(local_key, local_id, remote_key, remote_id) -> str:
    a = digits(fingerprint(local_key, local_id))
    b = digits(fingerprint(remote_key, remote_id))
    # same 60 digits on both phones
    return a + b if local_id <= remote_id else b + a

def pretty(sn): return " ".join(sn[i:i+5] for i in range(0, 60, 5))

def qr_payload(local_key, local_id, remote_key, remote_id) -> bytes:
    """Scannable form: version + both full 32-byte fingerprints, in a fixed
    order."""
    fa, fb = fingerprint(local_key, local_id)[:32], fingerprint(remote_key,
        remote_id)[:32]
    return b"\x00" + (fa + fb if local_id <= remote_id else fb + fa)

if __name__ == "__main__":
    # libsignal's NumericFingerprintGenerator test vector (identity keys
    # serialized as 0x05 ‖ key)
    alice_key = bytes.fromhex(
        "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
    bob_key = bytes.fromhex(
        "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
    a_id, b_id = b"+14152222222", b"+14153333333"
    sn = safety_number(alice_key, a_id, bob_key, b_id)
    print(f"  computed: {pretty(sn)}")
    want = '300354477692869396892869876765458257569162576843440918079131'
    print(f"  expected: {pretty(want)}")
    print(f"  match: {sn == want}")
    print(
        f"  Bob's phone shows the same number: "
        f"{safety_number(bob_key, b_id, alice_key, a_id) == sn}")
