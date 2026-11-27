# Listing 2.6 — ⚠️ INSECURE: ECDSA private-key recovery from a repeated nonce
# Pure-Python P-256 arithmetic for teaching only (not constant-time).
import hashlib, secrets

p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a  = p - 3
n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G  = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q: lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:      lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P, k = add(P, P), k >> 1
    return R

def h(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n

def sign(d: int, msg: bytes, k: int) -> tuple[int, int]:
    r = mul(k, G)[0] % n
    s = pow(k, -1, n) * (h(msg) + r * d) % n
    return r, s

def verify(Q, msg: bytes, sig) -> bool:
    r, s = sig
    w = pow(s, -1, n)
    X = add(mul(h(msg) * w % n, G), mul(r * w % n, Q))
    return X is not None and X[0] % n == r

d = secrets.randbelow(n - 1) + 1          # victim's private key
Q = mul(d, G)
# ⚠️ the bug: the same k for two signatures
k = secrets.randbelow(n - 1) + 1

m1, m2 = b"approve device phone-1", b"approve device tablet-2"
r1, s1 = sign(d, m1, k); r2, s2 = sign(d, m2, k)
assert verify(Q, m1, (r1, s1)) and verify(Q, m2, (r2, s2))
assert r1 == r2                            # the giveaway: identical r values

# Attacker: two equations, two unknowns (k, d).
k_rec = (h(m1) - h(m2)) * pow(s1 - s2, -1, n) % n
d_rec = (s1 * k_rec - h(m1)) * pow(r1, -1, n) % n
assert d_rec == d
print("recovered private key matches:", d_rec == d)
forged = sign(d_rec, b"approve device ATTACKER", secrets.randbelow(n - 1) + 1)
print("forged signature verifies:", verify(Q, b"approve device ATTACKER",
    forged))
