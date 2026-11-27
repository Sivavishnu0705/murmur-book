# Listing 2.2 — AES-256-GCM with associated data
import os, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def seal(key: bytes, plaintext: bytes, header: dict) -> tuple[bytes, bytes,
    bytes]:
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    nonce = os.urandom(12)                       # 96-bit random nonce
    # ciphertext || 16-byte tag
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct, aad

def open_(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    # raises InvalidTag on any change
    return AESGCM(key).decrypt(nonce, ct, aad)

if __name__ == "__main__":
    key = AESGCM.generate_key(bit_length=256)
    header = {"v": 1, "from": "alice", "to": "bob", "msg_id": 42}
    nonce, ct, aad = seal(key, b"Are you free at 7?", header)
    print("ciphertext+tag:", ct.hex(), f"({len(ct)} bytes = 18 + 16)")
    assert open_(key, nonce, ct, aad) == b"Are you free at 7?"

    # 1. Flip one ciphertext bit -> rejected.
    tampered = bytearray(ct); tampered[0] ^= 0x01
    try: open_(key, nonce, bytes(tampered), aad)
    except InvalidTag: print("tampered ciphertext: rejected")

    # 2. Change the header (AAD) -> rejected, though the header was never
    # encrypted.
    evil = json.dumps({**header, "to": "mallory"}, sort_keys=True,
                      separators=(",", ":")).encode()
    try: open_(key, nonce, ct, evil)
    except InvalidTag: print("tampered header (AAD): rejected")
