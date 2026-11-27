# attachments.py
"""Listing 21.4 — Python: attachment encryption, both designs, each with a
STREAMING decrypt that verifies before releasing data.
  A. Encrypt-then-MAC: AES-256-CBC + HMAC-SHA256 over IV ‖ ciphertext
  (Signal-style).
     Streaming decrypt = pass 1 verifies the MAC over the stored ciphertext,
     pass 2 decrypts.
  B. Chunked AEAD (STREAM): AES-256-GCM per 64 KiB chunk; nonce = 7-byte random
  prefix ‖
     32-bit chunk counter ‖ last-chunk flag byte. Each chunk is released only
     after its tag verifies; truncation is detected because the final chunk
     carries flag = 1."""
import hashlib, hmac, io, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding

BUF = 64 * 1024

# ─────────────── A. Encrypt-then-MAC (AES-CBC + HMAC-SHA256) ───────────────
def etm_encrypt(src, dst, key64):
    """key64 = 32-byte AES key ‖ 32-byte HMAC key (random per attachment).
    Returns the digest of the uploaded blob, which goes INSIDE the E2EE message
    with the key."""
    enc_key, mac_key = key64[:32], key64[32:]
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    pad = padding.PKCS7(128).padder()
    mac, blob_hash = hmac.new(mac_key,
        digestmod=hashlib.sha256), hashlib.sha256()
    def out(b):
        mac.update(b); blob_hash.update(b); dst.write(b)
    out(iv)
    while chunk := src.read(BUF):
        out(enc.update(pad.update(chunk)))
    out(enc.update(pad.finalize()) + enc.finalize())
    tag = mac.digest(); dst.write(tag); blob_hash.update(tag)
    return blob_hash.digest()

def etm_decrypt_stream(blob_file, size, key64, expected_digest):
    """Generator yielding plaintext blocks ONLY after the whole blob's MAC and
    digest verified."""
    enc_key, mac_key = key64[:32], key64[32:]
    mac, blob_hash = hmac.new(mac_key,
        digestmod=hashlib.sha256), hashlib.sha256()
    blob_file.seek(0); remaining = size - 32
    # pass 1: verify, release nothing
    while remaining:
        b = blob_file.read(min(BUF, remaining)); remaining -= len(b)
        mac.update(b); blob_hash.update(b)
    tag = blob_file.read(32); blob_hash.update(tag)
    if not hmac.compare_digest(mac.digest(),
        tag) or not hmac.compare_digest(blob_hash.digest(), expected_digest):
        raise ValueError("attachment MAC/digest mismatch: nothing released")
    blob_file.seek(0)
    iv = blob_file.read(16)
    remaining = size - 32 - 16   # pass 2: decrypt
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    while remaining:
        b = blob_file.read(min(BUF, remaining)); remaining -= len(b)
        yield unpad.update(dec.update(b))
    yield unpad.update(dec.finalize()) + unpad.finalize()

# ─────────────── B. Chunked AEAD (STREAM) ───────────────
def _nonce(prefix, i, last):
    return prefix + i.to_bytes(4, "big") + (b"\x01" if last else b"\x00")

def stream_encrypt(src, dst, key32):
    prefix = os.urandom(7)
    dst.write(prefix)                 # header: nonce prefix
    g, i = AESGCM(key32), 0
    cur = src.read(BUF)
    while True:
        nxt = src.read(BUF)
        last = not nxt
        # chunk = BUF bytes + 16-byte tag
        dst.write(g.encrypt(_nonce(prefix, i, last), cur, None))
        if last: return
        cur, i = nxt, i + 1

def stream_decrypt(blob_file, key32):
    """Yields each chunk after its tag verifies. Position (counter) and finality
    (flag) are in the nonce, so reordered, duplicated, dropped or truncated
    chunks fail. Until the generator finishes, the application must treat the
    output as INCOMPLETE (e.g. write to a temp file)."""
    g = AESGCM(key32)
    prefix = blob_file.read(7)
    i, cur = 0, blob_file.read(BUF + 16)
    while True:
        nxt = blob_file.read(BUF + 16)
        last = not nxt
        try:
            yield g.decrypt(_nonce(prefix, i, last), cur, None)
        except Exception:
            raise ValueError(
                f"chunk {i} failed authentication "
                f"({'final' if last else 'non-final'} position)")
        if last: return
        cur, i = nxt, i + 1

if __name__ == "__main__":
    import tracemalloc, time
    # an 8 MiB "video"
    data = os.urandom(8 * 1024 * 1024 + 12345)
    print("── A. Encrypt-then-MAC ──")
    k64, blob = os.urandom(64), io.BytesIO()
    digest = etm_encrypt(io.BytesIO(data), blob, k64)
    n = blob.tell()
    print(
        f"  roundtrip ok: "
        f"{b''.join(etm_decrypt_stream(blob, n, k64, digest)) == data}")
    bad = bytearray(blob.getvalue()); bad[n // 2] ^= 1
    try:
        released = 0
        for part in etm_decrypt_stream(io.BytesIO(bytes(bad)), n, k64, digest):
            released += len(part)
    except ValueError as e:
        print(
            f"  one bit flipped in the CDN copy: {e} (bytes released: "
            f"{released})")

    print("── B. Chunked AEAD (STREAM) ──")
    k32, blob = os.urandom(32), io.BytesIO()
    stream_encrypt(io.BytesIO(data), blob, k32)
    raw = blob.getvalue(); C = BUF + 16
    print(
        f"  roundtrip ok: "
        f"{b''.join(stream_decrypt(io.BytesIO(raw), k32)) == data}  "
        f"({(len(raw) - 7 + C - 1) // C} chunks)")
    chunks = [raw[7 + j * C: 7 + (j + 1) * C] for j in range((len(
        raw) - 7 + C - 1) // C)]
    attacks = {
        "swap chunks 3 and 4": raw[:7] + b"".join(chunks[:3] + [chunks[4],
        chunks[3]] + chunks[5:]),
        "truncate (drop final chunk)": raw[:7] + b"".join(chunks[:-1]),
        "drop a middle chunk": raw[:7] + b"".join(chunks[:10] + chunks[11:]),
    }
    for name, tampered in attacks.items():
        got = 0
        try:
            for part in stream_decrypt(io.BytesIO(tampered), k32): got += 1
            print(f"  {name}: ACCEPTED (!)")
        except ValueError as e:
            print(
                f"  {name}: {e}; {got} verified chunks released before the "
                f"failure")

    print(
        "── Memory: one-shot AES-GCM vs streaming (peak Python allocations) ──")
    for label, fn in [("one-shot AESGCM.encrypt(whole file)",
        lambda: AESGCM(k32).encrypt(os.urandom(12), data, None)),
        ("STREAM, 64 KiB chunks, to a file sink",
        lambda: stream_encrypt(io.BytesIO(data), open(os.devnull, "wb"), k32))]:
        tracemalloc.start()
        fn()
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"  {label:40} peak ≈ {peak / 1024 / 1024:6.2f} MiB")
