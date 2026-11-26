# Listing 2.10 — Murmur "tiny secure envelope" v1 (X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
# Save as envelope.py: Listing 2.13 imports it.
#
# Wire format:  version (1 byte = 0x01) || E (32 bytes, sender ephemeral pub) || ciphertext||tag
# Key schedule: dh  = X25519(e, R)                       (reject all-zero)
#               prk = HKDF-Extract(salt = E || R, ikm = dh)
#               okm = HKDF-Expand(prk, "murmur/v1/ch02/envelope", 44)
#               key = okm[0:32], nonce = okm[32:44]
# AEAD:         ChaCha20-Poly1305(key, nonce, plaintext, aad = version || E)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VERSION = b"\x01"
INFO = b"murmur/v1/ch02/envelope"
RAW_PUB = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def _pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(**RAW_PUB)

def _derive(dh: bytes, E: bytes, R: bytes) -> tuple[bytes, bytes]:
    if dh == bytes(32):
        raise ValueError("all-zero X25519 output: low-order public key")
    okm = HKDF(algorithm=hashes.SHA256(), length=44, salt=E + R, info=INFO).derive(dh)
    return okm[:32], okm[32:]

def seal(recipient_pub: bytes, plaintext: bytes,
         ephemeral: X25519PrivateKey | None = None) -> bytes:
    e = ephemeral or X25519PrivateKey.generate()   # fresh per message in real use
    E = _pub(e)
    dh = e.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    key, nonce = _derive(dh, E, recipient_pub)
    return VERSION + E + ChaCha20Poly1305(key).encrypt(nonce, plaintext, VERSION + E)

def open_(recipient: X25519PrivateKey, envelope: bytes) -> bytes:
    if len(envelope) < 1 + 32 + 16 or envelope[:1] != VERSION:
        raise ValueError("malformed envelope")
    E, ct = envelope[1:33], envelope[33:]
    R = _pub(recipient)
    dh = recipient.exchange(X25519PublicKey.from_public_bytes(E))
    key, nonce = _derive(dh, E, R)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, VERSION + E)

if __name__ == "__main__":
    # ---- Deterministic test vector (shared with Swift and Kotlin) ----
    r_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    e_sk = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    recipient = X25519PrivateKey.from_private_bytes(r_sk)
    eph = X25519PrivateKey.from_private_bytes(e_sk)
    R, E = _pub(recipient), _pub(eph)
    dh = eph.exchange(X25519PublicKey.from_public_bytes(R))
    key, nonce = _derive(dh, E, R)
    pt = b"Are you free at 7?"
    env = seal(R, pt, ephemeral=eph)
    assert open_(recipient, env) == pt
    for k, v in [("recipient_sk", r_sk), ("recipient_pk", R), ("ephemeral_sk", e_sk),
                 ("ephemeral_pk", E), ("dh", dh), ("key", key), ("nonce", nonce),
                 ("plaintext", pt), ("envelope", env)]:
        print(f"{k:13} = {v.hex()}")
