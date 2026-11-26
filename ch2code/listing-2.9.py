# Listing 2.9 — ⚠️ INSECURE: what AES-GCM nonce reuse leaks
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

key = AESGCM.generate_key(bit_length=128)
NONCE = b"\x00" * 12                     # ⚠️ the bug: a fixed nonce
p1 = b"Meet at the north gate at 19:00"
p2 = b"Transfer 5000 to account 99-114"

c1 = AESGCM(key).encrypt(NONCE, p1, None)[:-16]   # strip 16-byte tag
c2 = AESGCM(key).encrypt(NONCE, p2, None)[:-16]

# 1. The attacker sees only c1 and c2 — yet c1 XOR c2 == p1 XOR p2.
assert xor(c1, c2) == xor(p1, p2)
print("c1 XOR c2 == p1 XOR p2:", xor(c1, c2).hex())

# 2. If the attacker knows (or guesses) p1, p2 falls out immediately.
recovered = xor(xor(c1, c2), p1)
print("recovered p2:", recovered.decode())

# 3. Worse: the keystream itself is exposed, so the attacker can encrypt
#    anything of the same length. (Forging a valid *tag* also becomes
#    feasible once the authentication key H is recovered from two tags
#    under one nonce — see §2.5.)
keystream = xor(c1, p1)
forged_ct = xor(keystream, b"Meet at the south gate at 23:00")
print("forged ciphertext body:", forged_ct.hex())
