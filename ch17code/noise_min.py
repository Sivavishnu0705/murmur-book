# noise_min.py
"""Listing 17.1 — Python: the Noise state machine from the specification (§5), for XX only:
CipherState, SymmetricState (ck, h), HandshakeState. ~100 lines, written to be READ.
It is checked byte-for-byte against the library (Listing 17.2) below. Use the library in practice."""
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

HASHLEN = 32
PUB = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def HASH(d): return hashlib.sha256(d).digest()
def HMAC(k, d): return hmac.new(k, d, hashlib.sha256).digest()
def HKDF2(ck, ikm):                                   # Noise's HKDF with two outputs
    t = HMAC(ck, ikm); o1 = HMAC(t, b"\x01"); return o1, HMAC(t, o1 + b"\x02")
def DH(priv, pub): return priv.exchange(X25519PublicKey.from_public_bytes(pub))
def pub(priv): return priv.public_key().public_bytes(**PUB)

class CipherState:
    def __init__(self, k=None): self.k, self.n = k, 0
    def _nonce(self): return b"\x00" * 4 + self.n.to_bytes(8, "little")
    def encrypt(self, ad, pt):
        if self.k is None: return pt                  # before any MixKey: plaintext
        ct = ChaCha20Poly1305(self.k).encrypt(self._nonce(), pt, ad); self.n += 1; return ct
    def decrypt(self, ad, ct):
        if self.k is None: return ct
        pt = ChaCha20Poly1305(self.k).decrypt(self._nonce(), ct, ad); self.n += 1; return pt

class SymmetricState:
    def __init__(self, name, trace):
        self.h = name.ljust(HASHLEN, b"\x00") if len(name) <= HASHLEN else HASH(name)
        self.ck, self.cs, self.trace = self.h, CipherState(), trace
        self.log("InitializeSymmetric")
    def log(self, op):
        if self.trace is not None: self.trace.append((op, self.ck[:4].hex(), self.h[:4].hex(), self.cs.k is not None))
    def mix_hash(self, data, op="MixHash"):           # h = HASH(h ‖ data): transcript binding
        self.h = HASH(self.h + data); self.log(op)
    def mix_key(self, ikm, op):                       # ck, k = HKDF(ck, DH output): new key material
        self.ck, k = HKDF2(self.ck, ikm); self.cs = CipherState(k); self.log(op)
    def encrypt_and_hash(self, pt):                   # AEAD with h as associated data, then hash ct
        ct = self.cs.encrypt(self.h, pt); self.mix_hash(ct, "EncryptAndHash"); return ct
    def decrypt_and_hash(self, ct):
        pt = self.cs.decrypt(self.h, ct); self.mix_hash(ct, "DecryptAndHash"); return pt
    def split(self):
        k1, k2 = HKDF2(self.ck, b""); return CipherState(k1), CipherState(k2)

XX = [["e"], ["e", "ee", "s", "es"], ["s", "se"]]

class HandshakeState:
    def __init__(self, initiator, s, e, prologue, trace=None):
        self.ss = SymmetricState(b"Noise_XX_25519_ChaChaPoly_SHA256", trace)
        self.ss.mix_hash(prologue, "MixHash(prologue)")
        self.init, self.s, self.e, self.rs, self.re, self.i = initiator, s, e, None, None, 0
    def _dh(self, tok):                               # who uses which key depends on role
        a, b = tok
        mine = {"e": self.e, "s": self.s}
        theirs = {"e": self.re, "s": self.rs}
        if self.init: return DH(mine[a], theirs[b])
        return DH(mine[b], theirs[a])
    def write(self, payload):
        out = b""
        for tok in XX[self.i]:
            if tok == "e": out += pub(self.e); self.ss.mix_hash(pub(self.e), "MixHash(e)")
            elif tok == "s": out += self.ss.encrypt_and_hash(pub(self.s))
            else: self.ss.mix_key(self._dh(tok), f"MixKey({tok})")
        out += self.ss.encrypt_and_hash(payload); self.i += 1
        return out
    def read(self, msg):
        for tok in XX[self.i]:
            if tok == "e": self.re, msg = msg[:32], msg[32:]; self.ss.mix_hash(self.re, "MixHash(re)")
            elif tok == "s":
                n = 32 + (16 if self.ss.cs.k else 0)
                self.rs, msg = self.ss.decrypt_and_hash(msg[:n]), msg[n:]
            else: self.ss.mix_key(self._dh(tok), f"MixKey({tok})")
        self.i += 1
        return self.ss.decrypt_and_hash(msg)

if __name__ == "__main__":
    from noise.connection import NoiseConnection, Keypair
    from xx_lib import party, PRIV
    keys = {n: X25519PrivateKey.generate() for n in ("as", "ae", "bs", "be")}
    raw = {n: k.private_bytes(**PRIV) for n, k in keys.items()}
    trace = []
    A = HandshakeState(True, keys["as"], keys["ae"], b"murmur-demo/v1", trace)
    B = HandshakeState(False, keys["bs"], keys["be"], b"murmur-demo/v1")
    LA = party(True, raw["as"], b"murmur-demo/v1", raw["ae"])      # library, same keys
    LB = party(False, raw["bs"], b"murmur-demo/v1", raw["be"])
    m1 = A.write(b""); B.read(m1); l1 = LA.write_message(b""); LB.read_message(l1)
    m2 = B.write(b"hi"); A.read(m2); l2 = LB.write_message(b"hi"); LA.read_message(l2)
    m3 = A.write(b"yo"); B.read(m3); l3 = LA.write_message(b"yo"); LB.read_message(l3)
    print("── Fig 17.2: symmetric state evolution (initiator, Noise XX) ──")
    print(f"  {'operation':22} {'ck':10} {'h':10} key?")
    for op, ck, hh, k in trace:
        print(f"  {op:22} {ck:10} {hh:10} {'yes' if k else '—'}")
    print("── Interop check against the library ──")
    print(f"  messages identical:        {(m1, m2, m3) == (bytes(l1), bytes(l2), bytes(l3))}")
    print(f"  handshake hash identical:  {A.ss.h == LA.get_handshake_hash() == B.ss.h}")
    ia, ib = A.ss.split(); ra, rb = B.ss.split()
    print(f"  transport: {ra.decrypt(b'', ia.encrypt(b'', b'via split')) == b'via split'}")
