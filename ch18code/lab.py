# lab.py
"""Listing 18.7 — Python: lab — first secret between two Murmur users, then the property
differences with and without one-time prekeys, and a malicious server."""
import hashlib, json
from x3dh import KeyPair, Responder, initiate, DH, KDF, encode

alice_ik = KeyPair()
bob = Responder()                                    # publishes IK, SPK (signed), 3 OPKs

def safety_fp(ik_pub):                               # toy fingerprint; real safety numbers: Ch 20
    n = int.from_bytes(hashlib.sha512(encode(ik_pub)).digest()[:8], "big") % 10**12
    return f"{n:012d}"[:6] + " " + f"{n:012d}"[6:]

print("── First secret ──")
sk1, m1, _ = initiate(alice_ik, bob.bundle(), b"Hi Bob, it's Alice")
sk_b, pt = bob.receive(m1)
print(f"  with OPK #{m1['opk_id']}: SK agree={sk1 == sk_b}  Bob reads {pt!r}")
v = json.load(open("x3dh_vectors.json"))
vk = {n: KeyPair(bytes.fromhex(k["priv"])) for n, k in v["keys"].items()}
vbob = Responder(vk["ik_b"], vk["spk_b"], [vk["opk_b"]], z=b"\x42" * 64)
sk_v, _ = vbob.receive(initiate(vk["ik_a"], vbob.bundle(), b"hi Bob", vk["ek_a"], b"\0" * 12)[1])
print(f"  responder side reproduces the published test vector: {sk_v.hex() == v['with_opk']['sk']}")

print("── Replay of the initial message ──")
try:
    bob.receive(m1); print("  with OPK:    replay accepted (!)")
except KeyError:
    print("  with OPK:    replay rejected — the OPK's private key was deleted on first use")
bob.opks.clear()                                     # OPKs exhausted (or withheld by the server)
sk2, m2, _ = initiate(alice_ik, bob.bundle(), b"pay 100")
first, second = bob.receive(m2)[1], bob.receive(m2)[1]
print(f"  without OPK: replay accepted — Bob decrypts {first!r} twice: {first == second}")
seen = set()
def receive_with_cache(m):                           # mitigation: remember (SPK id, EK) while the SPK lives
    if (m["spk_id"], m["ek"]) in seen:
        raise ValueError("replayed initial message rejected by cache")
    seen.add((m["spk_id"], m["ek"])); return bob.receive(m)
receive_with_cache(m2)
try:
    receive_with_cache(m2)
except ValueError as e:
    print(f"  without OPK + replay cache: {e}")

print("── Forward secrecy: an attacker later steals Bob's IK and SPK private keys ──")
def attacker(m):
    km = DH(bob.spk, m["ik"]) + DH(bob.ik, m["ek"]) + DH(bob.spk, m["ek"])
    if "opk_id" in m:
        return None                                  # needs OPK private: deleted on first use
    return KDF(km)
print(f"  session WITH OPK:                     recovers SK? {attacker(m1) == sk1}")
print(f"  session WITHOUT OPK, SPK not rotated: recovers SK? {attacker(m2) == sk2}"
      "  ← until Bob deletes that SPK's private key")

print("── Malicious server ──")
b = bob.bundle(); evil = KeyPair()
try:
    initiate(alice_ik, dict(b, spk=evil.pub), b"x"); print("  swapped SPK accepted (!)")
except ValueError as e:
    print(f"  swaps SPK only:            {e}")
mitm = Responder()                                   # server's own IK + SPK + OPKs, self-signed
sk_m, m3, _ = initiate(alice_ik, mitm.bundle(), b"secret plans")
print(f"  swaps the WHOLE bundle:    X3DH completes; server reads {mitm.receive(m3)[1]!r}")
print(f"    Alice's screen, Bob's fingerprint: {safety_fp(mitm.ik.pub)}")
print(f"    Bob's screen,   his fingerprint:   {safety_fp(bob.ik.pub)}   → mismatch only if they COMPARE (Ch 20)")
