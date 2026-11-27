# x3dh.py
"""Listing 18.2 — Python: X3DH reference implementation (Signal's X3DH
specification), with deterministic test vectors. Parameters: curve X25519, hash
SHA-256, info "Murmur_X3DH_v1". Encode(PK) = 0x05 ‖ 32-byte little-endian
u-coordinate (the libsignal convention)."""
import json, os, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization as ser
import xeddsa

INFO = b"Murmur_X3DH_v1"
# X3DH §2.2: 32 0xFF bytes for X25519
F = b"\xff" * 32

class KeyPair:
    def __init__(self, priv_raw=None):
        self.k = X25519PrivateKey.from_private_bytes(
            priv_raw) if priv_raw else X25519PrivateKey.generate()
        self.priv = self.k.private_bytes(ser.Encoding.Raw,
            ser.PrivateFormat.Raw, ser.NoEncryption())
        self.pub = self.k.public_key().public_bytes(ser.Encoding.Raw,
            ser.PublicFormat.Raw)

def encode(pub):                                     # Encode(PK)
    return b"\x05" + pub

def DH(kp, pub):
    out = kp.k.exchange(X25519PublicKey.from_public_bytes(pub))
    # low-order point: reject (§18.8)
    if out == b"\x00" * 32:
        raise ValueError("invalid public key")
    return out

def KDF(km):
    return HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
        info=INFO).derive(F + km)

# ── Bob: identity key, signed prekey, one-time prekeys; the bundle he uploads
# ──
class Responder:
    def __init__(self, ik=None, spk=None, opks=(), z=None):
        self.ik, self.spk = ik or KeyPair(), spk or KeyPair()
        self.spk_id = 1
        # Sig(IK_B, Encode(SPK_B))
        self.spk_sig = xeddsa.sign(self.ik.priv, encode(self.spk.pub), z)
        self.opks = {i: kp for i,
            kp in enumerate(opks or [KeyPair() for _ in range(3)], start=1)}
    def bundle(self, with_opk=True):
        b = {"ik": self.ik.pub, "spk_id": self.spk_id, "spk": self.spk.pub,
            "spk_sig": self.spk_sig}
        if with_opk and self.opks:
            i = min(self.opks); b.update(opk_id=i, opk=self.opks[i].pub)
        return b

    def receive(self, msg):
        """Bob processes Alice's initial message."""
        if msg["spk_id"] != self.spk_id:
            raise ValueError("unknown signed prekey")
        dh1 = DH(self.spk, msg["ik"])                 # DH(IK_A, SPK_B)
        dh2 = DH(self.ik, msg["ek"])                  # DH(EK_A, IK_B)
        dh3 = DH(self.spk, msg["ek"])                 # DH(EK_A, SPK_B)
        km = dh1 + dh2 + dh3
        if "opk_id" in msg:
            # KeyError if already used: DELETE after use
            opk = self.opks.pop(msg["opk_id"])
            km += DH(opk, msg["ek"])                  # DH(EK_A, OPK_B)
        sk = KDF(km)
        # AD = Encode(IK_A) ‖ Encode(IK_B)
        ad = encode(msg["ik"]) + encode(self.ik.pub)
        pt = AESGCM(sk).decrypt(msg["nonce"], msg["ct"], ad)
        return sk, pt

# ── Alice: verify the bundle, compute the four DHs, send the initial message ──
def initiate(ik_a, bundle, plaintext, ek=None, nonce=None):
    if not xeddsa.verify(bundle["ik"], encode(bundle["spk"]),
        bundle["spk_sig"]):
        raise ValueError("signed prekey signature invalid: abort")
    ek = ek or KeyPair()
    dh1 = DH(ik_a, bundle["spk"])                     # authenticates Alice
    dh2 = DH(ek, bundle["ik"])                        # authenticates Bob
    dh3 = DH(ek, bundle["spk"])                       # forward secrecy
    km = dh1 + dh2 + dh3
    if "opk" in bundle:
        # one-time: FS + replay protection
        km += DH(ek, bundle["opk"])
    sk = KDF(km)
    ad = encode(ik_a.pub) + encode(bundle["ik"])
    nonce = nonce or os.urandom(12)
    msg = {"ik": ik_a.pub, "ek": ek.pub, "spk_id": bundle["spk_id"],
        "nonce": nonce,
        "ct": AESGCM(sk).encrypt(nonce, plaintext, ad)}
    if "opk" in bundle: msg["opk_id"] = bundle["opk_id"]
    # Alice deletes EK_A (and DH outputs) now
    del ek
    return sk, msg, (dh1, dh2, dh3, km[96:] if "opk" in bundle else b"")

# ── Deterministic test vectors (fixed keys) for cross-implementation checks ──
def vectors():
    seed = lambda n: bytes([n]) * 32
    ik_a, ek_a = KeyPair(seed(0x0A)), KeyPair(seed(0x0E))
    bob = Responder(KeyPair(seed(0x0B)), KeyPair(seed(0x5B)),
        [KeyPair(seed(0x0F))], z=b"\x42" * 64)
    out = {}
    for name, with_opk in (("with_opk", True), ("without_opk", False)):
        sk, msg, (d1, d2, d3, d4) = initiate(ik_a, bob.bundle(with_opk),
            b"hi Bob", ek_a, b"\x00" * 12)
        out[name] = {"dh1": d1.hex(), "dh2": d2.hex(), "dh3": d3.hex(),
            "dh4": d4.hex(), "sk": sk.hex(),
            "ad": (encode(ik_a.pub) + encode(bob.ik.pub)).hex(),
            "ct": msg["ct"].hex()}
    keys = {"ik_a": ik_a, "ek_a": ek_a, "ik_b": bob.ik, "spk_b": bob.spk,
        "opk_b": bob.opks[1]}
    return {"info": INFO.decode(), "spk_sig": bob.spk_sig.hex(),
            "keys": {n: {"priv": k.priv.hex(), "pub": k.pub.hex()} for n,
            k in keys.items()}, **out}

if __name__ == "__main__":
    v = vectors()
    json.dump(v, open("x3dh_vectors.json", "w"), indent=1)
    print(f"SPK signature (XEdDSA, Z=0x42*64): {v['spk_sig'][:32]}…")
    for case in ("with_opk", "without_opk"):
        print(f"{case:12} SK = {v[case]['sk']}")
