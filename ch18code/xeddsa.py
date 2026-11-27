# xeddsa.py
"""XEdDSA (Signal's specification) for X25519 keys, in pure Python, so identity
keys can be one X25519 key pair used for both DH and signatures. Educational and
NOT constant-time: production code uses libsignal. Verification here is standard
Ed25519 against the converted public key, which the test below cross-checks with
the `cryptography` package's Ed25519."""
import hashlib, os

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493          # group order
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)

def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p: x = x * I % p
    return p - x if x & 1 else x

By = 4 * pow(5, p - 2, p) % p
# extended coordinates (X, Y, Z, T)
B = (_xrecover(By), By, 1, _xrecover(By) * By % p)

def _add(P, Q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = P, Q
    a = (y1 - x1) * (y2 - x2) % p; b = (y1 + x1) * (y2 + x2) % p
    c = 2 * d * t1 * t2 % p; dd = 2 * z1 * z2 % p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)

def _mul(k, P):
    R = (0, 1, 1, 0)
    while k:
        if k & 1: R = _add(R, P)
        P = _add(P, P); k >>= 1
    return R

def _encode(P):
    x, y, z, _ = P
    zi = pow(z, p - 2, p); x, y = x * zi % p, y * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

def _clamp(k32):
    k = bytearray(k32); k[0] &= 248; k[31] &= 127; k[31] |= 64
    return int.from_bytes(k, "little")

def calculate_key_pair(x25519_private_raw):
    """Montgomery private key → Edwards (A, a) with A's sign bit forced to 0
    (XEdDSA §2.3)."""
    a = _clamp(x25519_private_raw) % q
    A = _encode(_mul(a, B))
    # negate so the sign bit is 0
    if A[31] & 0x80:
        a = (q - a) % q
        A = _encode(_mul(a, B))
    return A, a

def u_to_edwards(u_bytes):
    """Public conversion used by verifiers: y = (u - 1) / (u + 1), sign bit 0.
    """
    u = int.from_bytes(u_bytes, "little") % p
    y = (u - 1) * pow(u + 1, p - 2, p) % p
    return y.to_bytes(32, "little")

def _h(b): return int.from_bytes(hashlib.sha512(b).digest(), "little")

def sign(x25519_private_raw, msg, Z=None):
    """XEdDSA sign. Z: 64 random bytes (pass a fixed value ONLY for test
    vectors)."""
    A, a = calculate_key_pair(x25519_private_raw)
    Z = Z if Z is not None else os.urandom(64)
    # hash_1: domain-separated nonce hash
    prefix = b"\xfe" + b"\xff" * 31
    r = _h(prefix + a.to_bytes(32, "little") + msg + Z) % q
    R = _encode(_mul(r, B))
    h = _h(R + A + msg) % q
    s = (r + h * a) % q
    return R + s.to_bytes(32, "little")

def verify(x25519_public_raw, msg, sig):
    """Standard Ed25519 verification against the converted key (via
    `cryptography`)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= q:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(u_to_edwards(
            x25519_public_raw)).verify(sig, msg)
        return True
    except InvalidSignature:
        return False

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric.x25519 import \
        X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    ok = 0
    for _ in range(50):
        k = X25519PrivateKey.generate()
        priv = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw,
            s.NoEncryption())
        pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        A, _ = calculate_key_pair(priv)
        # private-side and public-side agree
        assert A == u_to_edwards(pub)
        sig = sign(priv, b"msg")
        ok += verify(pub, b"msg", sig) and not verify(pub, b"msg!", sig)
    print(
        f"XEdDSA: {ok}/50 signatures verify under standard Ed25519 with the "
        f"converted key")
