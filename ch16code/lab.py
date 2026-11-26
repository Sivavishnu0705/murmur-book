# lab.py
"""Listing 16.4 — Python: lab driver — exploit each toy, then run the fixed version."""
import time
import toys
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ake import RAW

def row(n, label, broken, fixed):
    print(f"  {n}  {label:44} broken: {broken:30} fixed: {fixed}")

print("── Attack five toy protocols ──")
yn = lambda b, yes, no: yes if b else no
row(1, "reflection (Alice accepts Mallory as bob?)",
    yn(toys.toy1(False), "ACCEPTED ← attack works", "rejected"), yn(toys.toy1(True), "accepted", "rejected"))
row(2, "misbinding (Bob accepts peer 'eve'?)",
    yn(toys.toy2(False), "ACCEPTED ← attack works", "rejected"), yn(toys.toy2(True), "accepted", "rejected"))
r_b, n_b = toys.toy3(False); r_f, n_f = toys.toy3(True)
row(3, "replay (recorded session replayed later)", f"{r_b}, payments run={n_b}", f"{r_f}, payments run={n_f}")
row(4, "KCI (leaked i_b → impersonate Alice?)",
    yn(toys.toy4(False), "YES ← attack works", "no"), yn(toys.toy4(True), "yes", "no"))
t = time.perf_counter(); ok_b, guess = toys.toy5(False); dt = time.perf_counter() - t
ok_f, _ = toys.toy5(True)
row(5, "downgrade (client completes on 'weak'?)",
    yn(ok_b, f"YES, key 0x{guess:04x} in {dt:.2f}s", "no"), yn(ok_f, "completes", "ABORT (transcript mismatch)"))

print("── §16.8: sizes on the wire (bytes), measured with this machine's library ──")
x = X25519PrivateKey.generate(); e = Ed25519PrivateKey.generate()
k = mlkem.MLKEM768PrivateKey.generate(); ss, ct = k.public_key().encapsulate()
print(f"  X25519 public key              {len(x.public_key().public_bytes(**RAW)):>5}")
print(f"  ML-KEM-768 encapsulation key   {len(k.public_key().public_bytes_raw()):>5}   ciphertext {len(ct):>5}   shared secret {len(ss)}")
print(f"  Ed25519 public key / signature {len(e.public_key().public_bytes(**RAW)):>5} / {len(e.sign(b'm'))}")
for cls in (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey):
    s = cls.generate()
    print(f"  {cls.__name__[:7]} public key / signature {len(s.public_key().public_bytes_raw()):>5} / {len(s.sign(b'm'))}")
