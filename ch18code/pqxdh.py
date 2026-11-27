# pqxdh.py
"""Listing 18.4 — Python: PQXDH variant (Signal's PQXDH, revision 3, simplified)
with ML-KEM-1024. Bob adds a signed post-quantum prekey; Alice encapsulates to
it; the KEM shared secret SS joins the DH outputs in the KDF. Authentication
remains classical (X25519 + XEdDSA)."""
import os
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import xeddsa
from x3dh import KeyPair, encode, DH, F

INFO = b"Murmur_CURVE25519_SHA-256_ML-KEM-1024"

# key-type byte binds the signature to "ML-KEM-1024 key"
def encode_kem(pk):
    return b"\x08" + pk

def KDF(km):
    return HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
        info=INFO).derive(F + km)

class PQResponder:
    def __init__(self):
        self.ik, self.spk, self.opk = KeyPair(), KeyPair(), KeyPair()
        # last-resort PQ prekey (signed); one-time PQOPKs work the same way
        self.pqspk = mlkem.MLKEM1024PrivateKey.generate()
        pq_pub = self.pqspk.public_key().public_bytes_raw()
        self.bundle = {"ik": self.ik.pub, "spk": self.spk.pub,
                       "spk_sig": xeddsa.sign(self.ik.priv,
                       encode(self.spk.pub)),
                       "opk": self.opk.pub,
                       "pqpk": pq_pub, "pqpk_sig": xeddsa.sign(self.ik.priv,
                       encode_kem(pq_pub))}
    def receive(self, m):
        ss = self.pqspk.decapsulate(m["ct_kem"])
        km = (DH(self.spk, m["ik"]) + DH(self.ik, m["ek"]) + DH(self.spk,
            m["ek"]) + DH(self.opk, m["ek"]))
        sk = KDF(km + ss)
        ad = encode(m["ik"]) + encode(self.ik.pub)
        return sk, AESGCM(sk).decrypt(m["nonce"], m["ct"], ad)

def pq_initiate(ik_a, b, plaintext):
    # Verify BOTH signatures; a server must not be able to swap in its own KEM
    # key.
    if not (xeddsa.verify(b["ik"], encode(b["spk"]), b["spk_sig"]) and
            xeddsa.verify(b["ik"], encode_kem(b["pqpk"]), b["pqpk_sig"])):
        raise ValueError("bundle signature invalid: abort")
    ek = KeyPair()
    ss, ct_kem = mlkem.MLKEM1024PublicKey.from_public_bytes(
        b["pqpk"]).encapsulate()
    dhs = DH(ik_a, b["spk"]) + DH(ek, b["ik"]) + DH(ek, b["spk"]) + DH(ek,
        b["opk"])
    sk = KDF(dhs + ss)
    ad = encode(ik_a.pub) + encode(b["ik"])
    nonce = os.urandom(12)
    m = {"ik": ik_a.pub, "ek": ek.pub, "ct_kem": ct_kem, "nonce": nonce,
         "ct": AESGCM(sk).encrypt(nonce, plaintext, ad)}
    return sk, m, dhs

if __name__ == "__main__":
    bob, alice = PQResponder(), KeyPair()
    sk_a, msg, dhs = pq_initiate(alice, bob.bundle, b"hello, post-quantum Bob")
    sk_b, pt = bob.receive(msg)
    print(f"  PQXDH: SK agree={sk_a == sk_b}  plaintext={pt!r}")

    # Harvest now, decrypt later: suppose a future quantum attacker recovers
    # EVERY X25519 secret from the recorded transcript (all four DH outputs) —
    # but not the ML-KEM shared secret.
    from x3dh import KDF as X3DH_KDF, Responder, initiate
    x_sk, _, (d1, d2, d3, d4) = initiate(alice, Responder().bundle(),
        b"classical")
    print(
        f"  plain X3DH session, attacker has all DH outputs: recovers SK? "
        f"{X3DH_KDF(d1 + d2 + d3 + d4) == x_sk}")
    print(
        f"  PQXDH session, attacker has all DH outputs:      recovers SK? "
        f"{KDF(dhs) == sk_a}  (also needs SS)")

    # Tampering: server swaps the PQ prekey for its own
    evil = mlkem.MLKEM1024PrivateKey.generate().public_key().public_bytes_raw()
    try:
        pq_initiate(alice, dict(bob.bundle, pqpk=evil), b"x")
        print("  swapped PQ prekey accepted (!)")
    except ValueError as e:
        print(f"  server swaps in its own PQ prekey: {e}")

    x3dh_bundle = 32 + 32 + 64 + 32
    pq_bundle = sum(len(v) for v in bob.bundle.values())
    print(
        f"  bundle size:          X3DH {x3dh_bundle} B   PQXDH {pq_bundle} B "
        f" (+{pq_bundle - x3dh_bundle})")
    x3dh_msg = 32 + 32
    print(
        f"  initial-message keys: X3DH {x3dh_msg} B    PQXDH "
        f"{x3dh_msg + len(msg['ct_kem'])} B  (+{len(msg['ct_kem'])} KEM "
        f"ciphertext)")
