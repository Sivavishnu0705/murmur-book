# Listing 7.4 — Python: HPKE (RFC 9180) single-shot encryption, base mode.
# Same job as Chapter 2's envelope, but standardized: use this, not a home-made design.
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)

recipient = X25519PrivateKey.generate()                 # e.g. a server's published key
info = b"murmur/v1/ch07/hpke-demo"                       # binds the ciphertext to its purpose

ct = suite.encrypt(b"Are you free at 7?", recipient.public_key(), info=info)
print(f"HPKE output: {len(ct)} bytes = 32 (enc: ephemeral X25519 key) + 18 (plaintext) + 16 (tag)")
print("decrypted  :", suite.decrypt(ct, recipient, info=info).decode())

try:
    suite.decrypt(ct, recipient, info=b"murmur/v1/some-other-purpose")
except Exception as e:
    print("wrong info :", type(e).__name__, "— context binding works")

# Post-quantum hybrid HPKE: same API, ML-KEM-768 + X25519 KEM (larger "enc").
pq_suite = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)
from cryptography.hazmat.primitives.asymmetric import mlkem
pq_recipient = hpke.MLKEM768X25519PrivateKey(mlkem.MLKEM768PrivateKey.generate(),
                                             X25519PrivateKey.generate())
pq_ct = pq_suite.encrypt(b"Are you free at 7?", pq_recipient.public_key(), info=info)
print(f"PQ hybrid  : {len(pq_ct)} bytes (enc grows from 32 to {len(pq_ct) - 34} bytes)")
assert pq_suite.decrypt(pq_ct, pq_recipient, info=info) == b"Are you free at 7?"
