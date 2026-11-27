# Listing 2.13 — ⚠️ INSECURE: "optimizing" the envelope by caching the ephemeral
# key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from envelope import seal, open_, _pub

bob = X25519PrivateKey.generate()
B = _pub(bob)

# ⚠️ "saves an X25519 op per message"
CACHED_EPHEMERAL = X25519PrivateKey.generate()
def seal_buggy(pub: bytes, pt: bytes) -> bytes:
    return seal(pub, pt, ephemeral=CACHED_EPHEMERAL)

m1 = b"My PIN for the shared account is 4417"
# attacker-influenced or guessable
m2 = b"Hi Bob! Lunch tomorrow? Bring the doc"
env1, env2 = seal_buggy(B, m1), seal_buggy(B, m2)
# functional tests pass!
assert open_(bob, env1) == m1 and open_(bob, env2) == m2

# Attacker view: both envelopes carry the same E -> same key and nonce.
assert env1[1:33] == env2[1:33]
c1, c2 = env1[33:-16], env2[33:-16]
leak = bytes(x ^ y for x, y in zip(c1, c2))
recovered = bytes(x ^ y for x, y in zip(leak, m2))
print("same ephemeral key in both envelopes:", env1[1:33] == env2[1:33])
print("recovered m1:", recovered.decode())
