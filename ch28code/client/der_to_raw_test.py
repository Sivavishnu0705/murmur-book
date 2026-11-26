# der_to_raw_test.py
"""A line-for-line Python port of Listing 28.1's derToRaw, run against real ECDSA signatures and
malformed inputs, so the strict DER rules in the (uncompiled) Kotlin are exercised."""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

def der_to_raw(der):
    i = 0
    def bad(): raise ValueError("malformed ECDSA signature")
    def byte():
        nonlocal i
        if i >= len(der): bad()
        b = der[i]; i += 1; return b
    def length():
        b = byte()
        if b < 0x80: return b
        if b == 0x81:
            n = byte()
            if n < 0x80: bad()
            return n
        bad()
    def scalar():
        nonlocal i
        if byte() != 0x02: bad()
        n = length()
        if n == 0 or n > 33 or i + n > len(der): bad()
        v = der[i:i + n]; i += n
        if v[0] & 0x80: bad()
        if n > 1 and v[0] == 0 and not v[1] & 0x80: bad()
        t = v[1:] if v[0] == 0 and n > 1 else v
        if len(t) > 32 or not any(t): bad()
        return bytes(32 - len(t)) + t
    if byte() != 0x30: bad()
    if length() != len(der) - i: bad()
    r = scalar(); s = scalar()
    if i != len(der): bad()
    return r + s

key = ec.generate_private_key(ec.SECP256R1()); ok = 0
for _ in range(2000):                                  # real signatures: short r/s, high bit set, …
    der = key.sign(os.urandom(16), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    assert der_to_raw(der) == r.to_bytes(32, "big") + s.to_bytes(32, "big"); ok += 1
print(f"  2000 real P-256 signatures: all converted correctly ({ok})")
good = encode_dss_signature(5, 7)
cases = {"trailing byte": good + b"\x00", "wrong outer length": bytes([0x30, good[1] + 1]) + good[2:],
         "r = 0": encode_dss_signature(0, 7), "negative s": bytes.fromhex("3006020105020181"),
         "non-minimal padding": bytes.fromhex("300702020005020107"), "not a SEQUENCE": b"\x31" + good[1:],
         "non-minimal long length": bytes.fromhex("30810602010502010" "7"), "truncated": good[:-1],
         "33-byte r > 256 bits": encode_dss_signature(1 << 256, 7)}
for name, der in cases.items():
    try: der_to_raw(der); print(f"  {name:<24} accepted (!)")
    except ValueError: print(f"  {name:<24} rejected")
