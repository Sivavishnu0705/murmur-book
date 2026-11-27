# ake.py
"""Shared helpers for Chapter 16's toy protocols. Real primitives (X25519,
Ed25519, HKDF-SHA256, HMAC-SHA256, AES-GCM); toy PROTOCOLS. Never deploy these
handshakes."""
import hmac, hashlib, os
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

RAW = dict(encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)

def dh_keypair():
    k = X25519PrivateKey.generate()
    return k, k.public_key().public_bytes(**RAW)

def dh(priv, pub_bytes):
    return priv.exchange(X25519PublicKey.from_public_bytes(pub_bytes))

def sig_keypair():
    k = Ed25519PrivateKey.generate()
    return k, k.public_key()

def verify(pub, sig, msg):
    try:
        pub.verify(sig, msg); return True
    except InvalidSignature:
        return False

def kdf(ikm, info, n=32, salt=b"\x00" * 32):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt,
        info=info).derive(ikm)

def mac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def mac_ok(key, msg, tag):
    return hmac.compare_digest(mac(key, msg), tag)

def h(*parts):
    """Unambiguous transcript hash: length-prefix every part (no concatenation
    ambiguity)."""
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big") + p)
    return d.digest()

def fp(b):  # short fingerprint for printing
    return b[:6].hex()
