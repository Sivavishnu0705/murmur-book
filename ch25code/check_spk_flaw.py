# check_spk_flaw.py
"""Listing 25.4 — Python: executable cross-check of the ProVerif model's flaw, using Chapter 18's
X3DH code. If Alice skips the SPK signature check, a malicious server can substitute a signed
prekey it controls; nothing fails immediately (Bob simply can't decrypt), but once Bob's
identity key leaks LATER, the server decrypts the recorded message. With the check, it cannot."""
import sys
sys.path.insert(0, "../../ch18code")
import x3dh
from x3dh import KeyPair, DH, KDF, encode

def attack(check_spk):
    alice_ik, bob = KeyPair(), x3dh.Responder()
    bundle = bob.bundle(with_opk=False)
    evil = KeyPair()                                       # server's own "signed prekey"
    tampered = dict(bundle, spk=evil.pub)
    orig = x3dh.xeddsa.verify
    if not check_spk:
        x3dh.xeddsa.verify = lambda *a: True               # the flawed client: no signature check
    try:
        sk, msg, _ = x3dh.initiate(alice_ik, tampered, b"the secret plan")
    except ValueError as e:
        return f"Alice refuses the bundle ({e})"
    finally:
        x3dh.xeddsa.verify = orig
    # Phase 1: Bob's identity private key leaks. Server recomputes Alice's three DHs:
    k = KDF(DH(evil, msg["ik"]) + DH(bob.ik, msg["ek"]) + DH(evil, msg["ek"]))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = AESGCM(k).decrypt(msg["nonce"], msg["ct"], encode(msg["ik"]) + encode(bob.ik.pub))
    return f"server decrypts the recorded message after the leak: {pt!r}"

print(f"  CHECK_SPK = false: {attack(False)}")
print(f"  CHECK_SPK = true:  {attack(True)}")
