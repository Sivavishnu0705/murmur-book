# senderkeys.py
"""Listing 22.1 — Python: sender keys with signing (the design used by Signal-protocol groups,
simplified). Each member device owns a sender chain: a chain key ratcheted forward with
HMAC-SHA256 (as in Ch 19's symmetric ratchet) and an Ed25519 signing key. It distributes
(chain id, iteration, chain key, signing public key) to every other member over the PAIRWISE
Double Ratchet sessions; after that, each group message costs ONE encryption."""
import hashlib, hmac, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.exceptions import InvalidSignature

MAX_FORWARD = 2000                                   # cap on how far one message can move a chain
MAX_SKIPPED = 2000                                   # cap on stored skipped keys per chain (oldest evicted)
# Production also expires stored skipped keys by age (Murmur: 30 days), as in Ch 19 §19.6.

def step(ck):                                        # (next chain key, message key)
    return hmac.new(ck, b"\x02", hashlib.sha256).digest(), hmac.new(ck, b"\x01", hashlib.sha256).digest()

def kn(mk):
    b = HKDF(hashes.SHA256(), 44, salt=None, info=b"murmur sender key msg v1").derive(mk)
    return b[:32], b[32:]

def raw(pub): return pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

class SenderChain:
    """My own sending state for one group."""
    def __init__(self, group, sender):
        self.group, self.sender = group, sender
        self.chain_id = os.urandom(4)
        self.iteration, self.ck = 0, os.urandom(32)
        self.sk = Ed25519PrivateKey.generate()
    def distribution(self):
        """SenderKeyDistributionMessage — sent to each member over the pairwise session."""
        return {"group": self.group, "sender": self.sender, "chain_id": self.chain_id,
                "iteration": self.iteration, "ck": self.ck, "sig_pub": raw(self.sk.public_key())}
    def encrypt(self, plaintext):
        self.ck, mk = step(self.ck)                      # advance first: the old chain key is gone
        it = self.iteration; self.iteration += 1
        key, nonce = kn(mk)
        hdr = self.group.encode() + b"|" + self.sender.encode() + b"|" + self.chain_id + it.to_bytes(4, "big")
        ct = AESGCM(key).encrypt(nonce, plaintext, hdr)
        return {"hdr": hdr, "group": self.group, "sender": self.sender, "chain_id": self.chain_id,
                "it": it, "ct": ct, "sig": self.sk.sign(hdr + ct)}  # signature: authenticity INSIDE the group

class ReceiverState:
    """What a member stores for each OTHER member's sender chain."""
    def __init__(self, verify_signatures=True):
        self.chains = {}                                 # (group, sender) → {chain_id, it, ck, pub, skipped}
        self.verify = verify_signatures
    def install(self, d):
        self.chains[(d["group"], d["sender"])] = {"chain_id": d["chain_id"], "it": d["iteration"],
            "ck": d["ck"], "pub": Ed25519PublicKey.from_public_bytes(d["sig_pub"]), "skipped": {}}
    def decrypt(self, m):
        c = self.chains.get((m["group"], m["sender"]))
        if c is None or c["chain_id"] != m["chain_id"]:
            raise KeyError("no sender key for this chain (not distributed to us / rotated away)")
        if self.verify:
            try: c["pub"].verify(m["sig"], m["hdr"] + m["ct"])
            except InvalidSignature: raise ValueError("bad sender signature")
        if m["it"] in c["skipped"]:
            mk = c["skipped"].pop(m["it"])
        else:
            if m["it"] < c["it"]: raise ValueError("old iteration: key already used and deleted")
            if m["it"] - c["it"] > MAX_FORWARD: raise ValueError("too far ahead")
            ck, it = c["ck"], c["it"]
            while it < m["it"]:
                ck, skipped_mk = step(ck); c["skipped"][it] = skipped_mk; it += 1
            while len(c["skipped"]) > MAX_SKIPPED:           # dicts keep insertion order: evict oldest
                c["skipped"].pop(next(iter(c["skipped"])))
            ck, mk = step(ck)
            c["ck"], c["it"] = ck, it + 1
        key, nonce = kn(mk)
        return AESGCM(key).decrypt(nonce, m["ct"], m["hdr"])
