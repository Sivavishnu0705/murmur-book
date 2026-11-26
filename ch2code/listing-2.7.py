# Listing 2.7 — Ed25519 signatures with a context string
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

if __name__ == "__main__":
    signer = Ed25519PrivateKey.generate()
    pub = signer.public_key()
    CONTEXT = b"murmur/v1/sig/device-list\x00"     # domain separation for signatures
    message = b'{"user":"bob","devices":["phone-1","tablet-2"],"version":7}'
    sig = signer.sign(CONTEXT + message)
    print("Ed25519 signature:", sig.hex(), f"({len(sig)} bytes)")
    pub.verify(sig, CONTEXT + message)               # raises InvalidSignature on failure
    print("verify with correct context: OK")
    try:
        pub.verify(sig, b"murmur/v1/sig/prekey\x00" + message)
    except InvalidSignature:
        print("verify under a different context: rejected")

    # Ed25519 is deterministic: same key + same message -> same signature.
    assert signer.sign(CONTEXT + message) == sig
    print("deterministic: OK")
