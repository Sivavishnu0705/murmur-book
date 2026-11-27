# Listing 2.1 — HKDF with labels (RFC 5869)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract = HMAC-Hash(salt, IKM). Returns the PRK."""
    import hmac, hashlib
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using the library (avoids hand-rolling the counter loop)."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
        info=info).derive(prk)

def label(purpose: str) -> bytes:
    # One namespace for every Murmur label: "murmur/<version>/<purpose>"
    return b"murmur/v1/" + purpose.encode("ascii")

if __name__ == "__main__":
    # RFC 5869 Test Case 1 — confirms our extract/expand match the spec.
    ikm  = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, info, 42)
    assert prk.hex() == \
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
        "ecc4c5bf34007208d5b887185865")
    print("RFC 5869 test case 1: OK")

    # Domain separation: one shared secret, several independent keys.
    shared_secret = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    prk = hkdf_extract(salt=b"murmur-session-salt", ikm=shared_secret)
    k_send   = hkdf_expand(prk, label("chat/send-key"), 32)
    k_recv   = hkdf_expand(prk, label("chat/recv-key"), 32)
    k_header = hkdf_expand(prk, label("chat/header-key"), 32)
    for name, k in [("send", k_send), ("recv", k_recv), ("header", k_header)]:
        print(f"{name:>6}: {k.hex()}")
    assert len({k_send, k_recv, k_header}) == 3

    # One-shot API (extract + expand) for the common case:
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"murmur-session-salt",
             info=label("chat/send-key")).derive(shared_secret)
    assert k == k_send
    print("one-shot HKDF matches two-step: OK")
