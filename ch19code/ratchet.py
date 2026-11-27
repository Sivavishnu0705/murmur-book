# ratchet.py
"""Listing 19.1 — Python: the Double Ratchet (Signal's specification, §3), with
headers, skipped message keys, MAX_SKIP, rollback on failed decryption, and
deterministic test vectors. KDF_RK = HKDF-SHA256 (salt = RK), KDF_CK =
HMAC-SHA256 with constants 0x01 / 0x02, ENCRYPT = AES-256-GCM with key and nonce
derived from the message key by HKDF."""
import copy, hmac, hashlib, json
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization as ser

# per chain: bounds work an attacker can force with a large n (§19.6)
MAX_SKIP = 1000
MAX_STORED = 2000        # total skipped keys kept; oldest evicted first
INFO_RK, INFO_MSG = b"Murmur_DR_Root_v1", b"Murmur_DR_Msg_v1"

class DHPair:
    def __init__(self, priv_raw=None):
        self.k = X25519PrivateKey.from_private_bytes(
            priv_raw) if priv_raw else X25519PrivateKey.generate()
        self.pub = self.k.public_key().public_bytes(ser.Encoding.Raw,
            ser.PublicFormat.Raw)
    def dh(self, pub):
        return self.k.exchange(X25519PublicKey.from_public_bytes(pub))

# → (new root key, new chain key)
def KDF_RK(rk, dh_out):
    out = HKDF(hashes.SHA256(), 64, salt=rk, info=INFO_RK).derive(dh_out)
    return out[:32], out[32:]

# → (next chain key, message key)
def KDF_CK(ck):
    return hmac.new(ck, b"\x02", hashlib.sha256).digest(), hmac.new(ck, b"\x01",
        hashlib.sha256).digest()

def ENCRYPT(mk, pt, ad):
    kn = HKDF(hashes.SHA256(), 44, salt=b"\x00" * 32, info=INFO_MSG).derive(mk)
    # nonce is unique only because mk is (§19.9!)
    return AESGCM(kn[:32]).encrypt(kn[32:], pt, ad)

def DECRYPT(mk, ct, ad):
    kn = HKDF(hashes.SHA256(), 44, salt=b"\x00" * 32, info=INFO_MSG).derive(mk)
    return AESGCM(kn[:32]).decrypt(kn[32:], ct, ad)

class Header:
    def __init__(self, dh, pn, n): self.dh, self.pn, self.n = dh, pn, n
    def encode(self): return self.dh + self.pn.to_bytes(4,
        "big") + self.n.to_bytes(4, "big")
    @staticmethod
    def decode(b): return Header(b[:32], int.from_bytes(b[32:36], "big"),
        int.from_bytes(b[36:40], "big"))

class Ratchet:
    """State variables exactly as in the specification."""
    def __init__(self, gen=DHPair):
        # key generator (injectable for test vectors)
        self.gen = gen
        # our ratchet key pair; their ratchet public key
        self.DHs = self.DHr = None
        self.RK = self.CKs = self.CKr = None
        self.Ns = self.Nr = self.PN = 0
        # (their ratchet pub, n) → message key, insertion-ordered
        self.MKSKIPPED = {}

    @classmethod
    # Alice = X3DH initiator
    def init_alice(cls, SK, bob_ratchet_pub, gen=DHPair):
        s = cls(gen)
        s.DHs, s.DHr = s.gen(), bob_ratchet_pub
        s.RK, s.CKs = KDF_RK(SK, s.DHs.dh(s.DHr))
        return s

    @classmethod
    # Bob's ratchet key = his SPK (§19.8)
    def init_bob(cls, SK, bob_ratchet_pair, gen=DHPair):
        s = cls(gen)
        s.DHs, s.RK = bob_ratchet_pair, SK
        return s

    def encrypt(self, pt, ad):
        self.CKs, mk = KDF_CK(self.CKs)
        h = Header(self.DHs.pub, self.PN, self.Ns)
        self.Ns += 1
        # header is authenticated, not secret
        return h.encode(), ENCRYPT(mk, pt, ad + h.encode())

    def decrypt(self, header_bytes, ct, ad):
        # Work on a COPY and commit only after successful decryption: a forged
        # or corrupted message must never advance (or wreck) the real state.
        trial = copy.copy(self); trial.MKSKIPPED = dict(self.MKSKIPPED)
        pt = trial._decrypt(Header.decode(header_bytes), header_bytes, ct, ad)
        self.__dict__.update(trial.__dict__)
        return pt

    def _decrypt(self, h, hb, ct, ad):
        mk = self.MKSKIPPED.pop((h.dh, h.n), None)
        # a late, out-of-order message
        if mk is not None:
            return DECRYPT(mk, ct, ad + hb)
        # new ratchet key: turn the DH ratchet
        if h.dh != self.DHr:
            # store keys of the old chain's stragglers
            self._skip(h.pn)
            self._dh_ratchet(h)
        self._skip(h.n)
        self.CKr, mk = KDF_CK(self.CKr)
        self.Nr += 1
        # raises on tampering → state not committed
        return DECRYPT(mk, ct, ad + hb)

    def _skip(self, until):
        if self.Nr + MAX_SKIP < until:
            raise ValueError(
                f"too many skipped messages ({until - self.Nr} > MAX_SKIP)")
        if self.CKr is not None:
            while self.Nr < until:
                self.CKr, mk = KDF_CK(self.CKr)
                self.MKSKIPPED[(self.DHr, self.Nr)] = mk
                self.Nr += 1
            # bounded storage: evict oldest
            while len(self.MKSKIPPED) > MAX_STORED:
                self.MKSKIPPED.pop(next(iter(self.MKSKIPPED)))

    def _dh_ratchet(self, h):
        self.PN, self.Ns, self.Nr = self.Ns, 0, 0
        self.DHr = h.dh
        # receiving chain
        self.RK, self.CKr = KDF_RK(self.RK, self.DHs.dh(self.DHr))
        # fresh key pair: healing
        self.DHs = self.gen()
        # sending chain
        self.RK, self.CKs = KDF_RK(self.RK, self.DHs.dh(self.DHr))

    # "state theft": copy everything
    def __deepcopy__(self, memo):
        c = copy.copy(self); c.MKSKIPPED = dict(self.MKSKIPPED); return c

# ── test vectors: fixed SK, fixed keys, deterministic ratchet key sequence ──
def vectors():
    seq = iter(bytes([i]) * 32 for i in range(0x20, 0x40))
    gen = lambda: DHPair(next(seq))
    SK, AD = bytes(range(32)), b"\x05" + b"\xaa" * 32 + b"\x05" + b"\xbb" * 32
    bob_spk = DHPair(b"\x5b" * 32)
    alice = Ratchet.init_alice(SK, bob_spk.pub, gen)
    bob = Ratchet.init_bob(SK, bob_spk, gen)
    script = [("A", b"a1"), ("A", b"a2"), ("B", b"b1"), ("A", b"a3"), ("B",
        b"b2"), ("B", b"b3")]
    out = []
    for who, pt in script:
        snd, rcv = (alice, bob) if who == "A" else (bob, alice)
        hb, ct = snd.encrypt(pt, AD)
        assert rcv.decrypt(hb, ct, AD) == pt
        out.append({"from": who, "header": hb.hex(), "ct": ct.hex(),
            "rk_after_recv": rcv.RK.hex()})
    return {"sk": SK.hex(), "ad": AD.hex(),
        "bob_spk_priv": (b"\x5b" * 32).hex(),
        "ratchet_privs": "0x20.. repeated bytes, in order of generation",
        "messages": out}

if __name__ == "__main__":
    v = vectors()
    json.dump(v, open("dr_vectors.json", "w"), indent=1)
    for m in v["messages"]:
        print(
            f"  {m['from']}→  header {m['header'][:16]}…  "
            f"n={int(m['header'][72:80], 16)} pn={int(m['header'][64:72], 16)}"
            f"   ct {m['ct'][:16]}…  RK(after) {m['rk_after_recv'][:12]}…")
