# Listing 2.4 — X25519 key agreement
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

RAW = dict(encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)

def x25519_shared(priv: X25519PrivateKey, peer_pub_raw: bytes) -> bytes:
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_raw))
    # RFC 7748 §6.1: reject the all-zero output (peer sent a low-order point).
    if shared == bytes(32):
        raise ValueError("X25519 produced all-zero shared secret")
    return shared

if __name__ == "__main__":
    alice, bob = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    a_pub = alice.public_key().public_bytes(**RAW)     # 32 bytes, sent to Bob
    b_pub = bob.public_key().public_bytes(**RAW)       # 32 bytes, sent to Alice
    s1, s2 = x25519_shared(alice, b_pub), x25519_shared(bob, a_pub)
    assert s1 == s2
    print("X25519 shared secret:", s1.hex())
    # NOTE: s1 is *not* a key yet. Always feed it through HKDF (Listing 2.1).

    # RFC 7748 §6.1 test vector: proves we interoperate with every other X25519.
    a = X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    b = X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    k = x25519_shared(a, b.public_key().public_bytes(**RAW))
    assert k.hex() == \
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    print("RFC 7748 test vector: OK")
