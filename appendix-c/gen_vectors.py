# gen_vectors.py
"""Appendix C — regenerates and checks Murmur's published test vectors from the book's own code.
Deterministic inputs everywhere; the one random value (an ML-KEM ciphertext) is recorded once
in pqxdh_vector.json and then only verified. Run from any directory."""
import hashlib, json, os, sys, struct
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in ("ch18code", "ch20code", "ch29code/spec"): sys.path.insert(0, os.path.join(B, d))
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
import x3dh, pqxdh, safety, murmur_pb2 as pb
sys.path.insert(0, os.path.join(B, "ch19code")); import importlib; ratchet = importlib.import_module("ratchet")

def wrap(h, w=64, ind=""): return ("\n" + ind).join(h[i:i + w] for i in range(0, len(h), w))
def sec(t): print(f"\n── {t} ──")

# C.1 Label registry: HKDF-SHA256(salt = 32×00, IKM = 00..1f, info = label, L = 32)
sec("C.1 KDF labels: HKDF-SHA256(salt=00×32, ikm=000102…1f, info=label, L=32)")
for lab in (b"Murmur_X3DH_v1", b"Murmur_CURVE25519_SHA-256_ML-KEM-1024", b"Murmur_DR_Root_v1",
            b"Murmur_DR_Msg_v1", b"murmur sealed sender v1", b"murmur sender key msg v1"):
    okm = HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32, info=lab).derive(bytes(range(32)))
    print(f"  {lab.decode():<40} {okm.hex()}")

# C.2 X3DH (Listing 18.2 vectors), recomputed and compared with the published file
sec("C.2 X3DH (info Murmur_X3DH_v1; XEdDSA nonce Z = 42×64; AES-GCM nonce 00×12)")
v = x3dh.vectors(); pub = json.load(open(os.path.join(B, "ch18code/x3dh_vectors.json")))
assert v == pub, "X3DH vectors changed!"
for n, k in v["keys"].items(): print(f"  {n:<6} priv {k['priv'][:2]}×32   pub {k['pub']}")
print(f"  SPK_B signature   {wrap(v['spk_sig'], 64, ' ' * 20)}")
for case in ("with_opk", "without_opk"):
    c = v[case]; print(f"  [{case}]")
    for f in ("dh1", "dh2", "dh3", "dh4"):
        if c.get(f): print(f"    {f:<4} {c[f]}")
    print(f"    SK   {c['sk']}\n    ct('hi Bob') {c['ct']}")

# C.3 PQXDH: same X25519 keys + ML-KEM-1024 key from seed 42×64 (FIPS 203 d‖z seed form)
sec("C.3 PQXDH (info Murmur_CURVE25519_SHA-256_ML-KEM-1024)")
kem = mlkem.MLKEM1024PrivateKey.from_seed_bytes(b"\x42" * 64)
ek = kem.public_key().public_bytes_raw()
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pqxdh_vector.json")
if not os.path.exists(path):
    ss, ct = kem.public_key().encapsulate()
    json.dump({"ct": ct.hex()}, open(path, "w"))
ct = bytes.fromhex(json.load(open(path))["ct"]); ss = kem.decapsulate(ct)
d = v["with_opk"]; dhs = b"".join(bytes.fromhex(d[f]) for f in ("dh1", "dh2", "dh3", "dh4"))
sk = pqxdh.KDF(dhs + ss)
print(f"  ML-KEM-1024 seed        42×64")
print(f"  ek (1568 B) SHA-256     {hashlib.sha256(ek).hexdigest()}")
print(f"  ct (1568 B) SHA-256     {hashlib.sha256(ct).hexdigest()}")
print(f"  SS = Decaps(dk, ct)     {ss.hex()}")
print(f"  DH1‖DH2‖DH3‖DH4         from C.2 [with_opk]")
print(f"  SK                      {sk.hex()}")
print(f"  ct, in full:\n    {wrap(ct.hex(), 64, '    ')}")

# C.4 Double Ratchet (Listing 19.1 vectors), recomputed and compared
sec("C.4 Double Ratchet (SK 00..1f; ratchet keys 20×32, 21×32, … in generation order)")
r = ratchet.vectors(); pub = json.load(open(os.path.join(B, "ch19code/dr_vectors.json")))
assert r == pub, "ratchet vectors changed!"
print(f"  AD {r['ad']}\n  Bob SPK priv 5b×32")
for i, m in enumerate(r["messages"], 1):
    print(f"  {i}. {m['from']}  header {m['header']}\n     ct {m['ct']}\n     RK after receive {m['rk_after_recv']}")

# C.5 Safety numbers (Listing 20.2): X3DH identity keys from C.2
sec("C.5 Safety number (5,200 × SHA-512, version 0x0000)")
ika, ikb = bytes.fromhex(v["keys"]["ik_a"]["pub"]), bytes.fromhex(v["keys"]["ik_b"]["pub"])
sn = safety.safety_number(ika, b"alice@murmur.example", ikb, b"bob@murmur.example")
assert sn == safety.safety_number(ikb, b"bob@murmur.example", ika, b"alice@murmur.example")
print(f"  alice IK = ik_a.pub, id 'alice@murmur.example';  bob IK = ik_b.pub, id 'bob@murmur.example'")
print(f"  displayed  {safety.pretty(sn)}")
print(f"  QR payload {safety.qr_payload(ika, b'alice@murmur.example', ikb, b'bob@murmur.example').hex()}")

# C.6 Encodings
sec("C.6 Encodings")
env = pb.Envelope(version=1, type=pb.RATCHET_MESSAGE, recipient_device="dev-8f2c1a", content=bytes(range(16)))
print(f"  Envelope(version=1, type=RATCHET_MESSAGE, recipient_device='dev-8f2c1a', content=00..0f)")
print(f"    protobuf  {env.SerializeToString(deterministic=True).hex()}")
put = lambda s: struct.pack(">I", len(s)) + s
dl = put(b"murmur device list v1") + put(b"alice") + struct.pack(">Q", 2) + struct.pack(">I", 1) \
     + put(b"dev-0001") + ika + put(b"Pixel") + struct.pack(">q", 1767225600)
print(f"  device list: account 'alice', version 2, one device (id 'dev-0001', IK = ik_a.pub, name 'Pixel', added 1767225600)")
print(f"    bytes     {wrap(dl.hex(), 64, ' ' * 14)}")
fr = len(b"murmur sender cert v1").to_bytes(2, "big") + b"murmur sender cert v1"
for f in (b"alice", b"dev-0001", ika, struct.pack(">Q", 1767312000)): fr += len(f).to_bytes(4, "big") + f
print(f"  Framed('murmur sender cert v1', 'alice', 'dev-0001', ik_a.pub, u64 1767312000)")
print(f"    bytes     {wrap(fr.hex(), 64, ' ' * 14)}")
print("\nall recomputed vectors match the published files")
