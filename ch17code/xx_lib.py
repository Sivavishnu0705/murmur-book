# xx_lib.py
"""Listing 17.2 — Python: Noise XX with a maintained library (`noiseprotocol`), then transport
messages and rekeying. Noise_XX_25519_ChaChaPoly_SHA256:
    XX:  -> e
         <- e, ee, s, es
         -> s, se
"""
from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
PRIV = dict(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
PUB = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def static_key():
    k = X25519PrivateKey.generate()
    return k.private_bytes(**PRIV), k.public_key().public_bytes(**PUB)

def party(initiator, static_priv, prologue, ephemeral_priv=None):
    c = NoiseConnection.from_name(NAME)
    c.set_as_initiator() if initiator else c.set_as_responder()
    c.set_keypair_from_private_bytes(Keypair.STATIC, static_priv)
    if ephemeral_priv:                     # only for interop testing (Listing 17.1); never in production
        c.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral_priv)
    c.set_prologue(prologue)               # bound into h: both sides must agree on context
    c.start_handshake()
    return c

def read(c, msg):
    """read_message, also returning the peer's static key once learned. The library discards its
    HandshakeState when the handshake completes, so keep a reference across the call."""
    hs = c.noise_protocol.handshake_state
    payload = c.read_message(msg)
    rs = getattr(hs, "rs", None)
    return payload, (rs.public_bytes if rs is not None and hasattr(rs, "public_bytes") else None)

if __name__ == "__main__":
    prologue = b"murmur-demo/v1"
    a_priv, a_pub = static_key(); b_priv, b_pub = static_key()
    alice, bob = party(True, a_priv, prologue), party(False, b_priv, prologue)

    m1 = alice.write_message(b"")                    # -> e
    read(bob, m1)
    m2 = bob.write_message(b"hello from bob")         # <- e, ee, s, es   (payload is encrypted)
    p2, bob_static = read(alice, m2)
    print(f"  msg 2 payload decrypted by Alice: {bytes(p2)!r}")
    m3 = alice.write_message(b"hello from alice")     # -> s, se
    p3, alice_static = read(bob, m3)
    print(f"  msg 3 payload decrypted by Bob:   {bytes(p3)!r}")
    print(f"  message sizes: {len(m1)}, {len(m2)}, {len(m3)} bytes")
    print(f"  Alice learned Bob's static key:   {bob_static == b_pub}")
    print(f"  Bob learned Alice's static key:   {alice_static == a_pub}")
    hh_a, hh_b = alice.get_handshake_hash(), bob.get_handshake_hash()
    print(f"  handshake hash equal:              {hh_a == hh_b}  ({hh_a[:8].hex()}…)")

    # Transport phase: two CipherStates, one per direction, with implicit 64-bit nonces.
    for i in range(3):
        ct = alice.encrypt(f"message {i}".encode())
        assert bob.decrypt(ct) == f"message {i}".encode()
    print(f"  transport: 3 messages Alice→Bob ok; ciphertext overhead = {len(ct) - len('message 2')} bytes (tag)")
    ct = alice.encrypt(b"replayed?")
    bob.decrypt(ct)
    try:
        bob.decrypt(ct)                               # same ciphertext again: nonce has moved on
        print("  replayed transport message: accepted (!)")
    except Exception as e:
        print(f"  replayed transport message: rejected ({type(e).__name__})")
    alice.rekey_outbound_cipher(); bob.rekey_inbound_cipher()   # Rekey(): k = ENCRYPT(k, maxnonce, …)
    print(f"  after Rekey on both sides:         {bob.decrypt(alice.encrypt(b'still in sync')) == b'still in sync'}")
