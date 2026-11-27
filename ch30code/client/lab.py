# lab.py
"""Listing 30.7 — Python: lab driver — group chat across five devices. Alice
(phone + tablet), Bob (iPhone + iPad) and Carol (phone) form a group through the
Chapter 27–30 server, using the real Rust/OpenMLS core over UniFFI: creation,
messages, a commit race, Authentication Service refusals, removal, a lost device
removed everywhere, a replacement device added everywhere, a leave, a
post-compromise update — and removed devices that cannot decrypt."""
import json, os, shutil, subprocess, sys, tempfile, time, atexit
HERE = os.path.dirname(os.path.abspath(__file__))
BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch20code", "ch21code/attach",
    "ch29code/spec", "ch27code/lab", "ch28code/client",
    "ch29code/client", "ch30code/core/py"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import x3dh, xeddsa
import murmur_groups as mg
from murmur_client import Edge, encode_device_list, b64, unb64
from messenger import Messenger, Edge29
from group_service import GroupService, SqlCipherMlsStore, VerifiedDirectory

root = tempfile.mkdtemp(prefix="murmur30-"); lab = os.path.join(root, "server")
srv = subprocess.Popen([sys.argv[1], "-out", lab], stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, text=True)
atexit.register(srv.kill)
assert srv.stdout.readline().strip() == "ready"
edge = Edge29(Edge(lab, json.load(open(os.path.join(lab, "ready.json")))))
attest = ser.load_pem_private_key(open(os.path.join(lab,
    "lab-attestation-key.pem"), "rb").read(), None)
cert_pub = ser.load_pem_public_key(open(os.path.join(lab,
    "sender-cert-key.pub"), "rb").read())
APPS = {"android": "example.murmur:SHA256:8F:1C:…",
    "ios": "TEAMID1234.example.murmur"}
T0 = time.time()

def aik_of(m): return Ed25519PrivateKey.from_private_bytes(m.store.identity(
    "account_identity")[1])
def device(account, platform, name, aik=None):
    m = Messenger(edge, account, platform, APPS[platform], attest,
        os.path.join(root, name), "push-" + name, cert_pub=cert_pub)
    m.login(phr=True); m.create_identity()
    if aik is not None:
        m.store.db.execute("DELETE FROM identity WHERE name='account_identity'")
        m.store.put_identity("account_identity",
            aik.public_key().public_bytes_raw(),
            aik.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw,
            ser.NoEncryption()))
    m.register_keys(T0)
    return m
def publish(signer, account, devs, version):
    enc = encode_device_list(account, version, [{"id": d.device_id,
        "ik": d.ik.pub, "name": d.platform, "added": 1} for d in devs])
    return signer.call("PUT", "/v1/devicelist", {"encoded": b64(enc),
        "signature": b64(aik_of(signer).sign(enc))})[0]

print("── 1. Five devices, three accounts ──")
ap = device("alice", "android", "alice-phone")
ap.call("PUT", "/v1/aik",
    {"aik": b64(aik_of(ap).public_key().public_bytes_raw())})
at = device("alice", "android", "alice-tablet", aik_of(ap))
publish(ap, "alice", [ap, at], 1)
bi = device("bob", "ios", "bob-iphone")
bi.call("PUT", "/v1/aik",
    {"aik": b64(aik_of(bi).public_key().public_bytes_raw())})
bp = device("bob", "ios", "bob-ipad", aik_of(bi))
publish(bi, "bob", [bi, bp], 1)
cp = device("carol", "android", "carol-phone")
cp.call("PUT", "/v1/aik",
    {"aik": b64(aik_of(cp).public_key().public_bytes_raw())})
publish(cp, "carol", [cp], 1)
M = {"alice-phone": ap, "alice-tablet": at, "bob-iphone": bi, "bob-ipad": bp,
    "carol-phone": cp}
G = {}
for n, m in M.items():
    # verified device lists (Ch 20)
    for acct in ("alice", "bob", "carol"): m.refresh_contact(acct)
    G[n] = GroupService(m)
    st = G[n].publish_key_packages(5)
    print(
        f"  {n:<13} {m.device_id}: MLS credential bound to its identity key; "
        f"5 KeyPackages + 1 last resort → {st}")

print(
    "── 2. Alice creates the group (admin: alice) and adds every device of "
    "every member ──")
gid, epoch = G["alice-phone"].create(["alice"], ["alice", "bob", "carol"])
print(
    f"  group {gid.hex()[:8]}…: one Commit adds 4 devices → DS 202, merged, "
    f"epoch {epoch}")
for n in ("alice-tablet", "bob-iphone", "bob-ipad", "carol-phone"):
    for r in G[n].receive():
        print(
            f"  {n:<13} {r[0]}: {r[2]}" if r[0] == "joined" else
            f"  {n:<13} {r}")
codes = {n: g.safety_code(gid) for n, g in G.items()}
print(
    f"  group safety code (epoch authenticator) on all five devices: "
    f"{set(codes.values())}")

print("── 3. Messages ──")
for n, text in (("bob-iphone", "hi all — the eagle lands at nine"),
    ("carol-phone", "hello from carol")):
    st, size = G[n].send(gid, text)
    print(f"  {n} sends ({size} B on the wire) → {st}")
for n in G:
    got = [r for r in G[n].receive() if r[0] == "message"]
    print(f"  {n:<13} decrypted: {[f'{s}: {t}' for _, s, t in got]}")

print(
    "── 4. A commit race: Bob's iPhone and Carol update at the same moment ──")
o_b = G["bob-iphone"].core.self_update(gid)
o_c = G["carol-phone"].core.self_update(gid)
for n, o in (("bob-iphone", o_b), ("carol-phone", o_c)):
    members = [x.split("/", 1)[1] for x in G[n].core.members(gid)]
    st, js = M[n].call("POST", "/v1/groups/commit", {"message": b64(o.commit),
        "members": members, "joiners": []})
    print(
        f"  {n} submits its epoch-{o.epoch - 1} Commit → {st} "
        f"{js.get('code', '')}")
    if st == 202: G[n].core.merge_pending(gid)
    else:
        G[n].core.clear_pending(gid)
        print(
            f"    → clears its pending commit, processes the winner: "
            f"{G[n].receive()}")
        e, attempts = G[n].self_update(gid)
        print(f"    → rebuilds and resubmits → merged at epoch {e}")
for n in G: G[n].receive()
print(
    f"  epochs: {sorted({g.core.epoch(gid) for g in G.values()})}; one "
    f"safety code: {len({g.safety_code(gid) for g in G.values()}) == 1}")

print(
    "── 5. Authentication Service and admin checks (all refused BEFORE "
    "anything is sent) ──")
mallory = device("mallory", "android", "mallory-phone")
mallory.call("PUT", "/v1/aik",
    {"aik": b64(aik_of(mallory).public_key().public_bytes_raw())})
gm = GroupService(mallory); gm.publish_key_packages(1)
kp_m = G["alice-phone"]._claim(mallory.device_id)
try: G["alice-phone"].core.add_members(gid, [kp_m])
except mg.GroupError as e:
    print(
        f"  alice adds a KeyPackage from a device in no verified list: "
        f"{getattr(e, 'msg', e)}")
publish(mallory, "mallory", [mallory], 1); ap.refresh_contact("mallory")
# MLS key signed by the WRONG identity key
class LyingBinder(mg.CredentialBinder):
    def bind(self, message): return xeddsa.sign(x3dh.KeyPair().priv, message)
evil = mg.MurmurGroups.open("mallory", mallory.device_id,
    SqlCipherMlsStore(Messenger(edge, "mallory", "android", APPS["android"],
       attest, os.path.join(root, "evil"), cert_pub=cert_pub).db),
       VerifiedDirectory(mallory), LyingBinder())
try: G["alice-phone"].core.add_members(gid, evil.key_packages(1, False))
except mg.GroupError as e:
    print(
        f"  alice adds a KeyPackage whose MLS key the device identity key "
        f"never signed: {getattr(e, 'msg', e)}")
cp.refresh_contact("mallory")
try:
    G["carol-phone"].core.add_members(gid,
        [G["carol-phone"]._claim(mallory.device_id)])
except mg.GroupError as e:
    print(f"  carol (not an admin) adds mallory: {getattr(e, 'msg', e)}")
try: G["bob-iphone"].core.remove_members(gid, [f"carol/{cp.device_id}"])
except mg.GroupError as e:
    print(f"  bob (not an admin) removes carol: {getattr(e, 'msg', e)}")

print("── 6. Alice removes Carol; Carol cannot read what follows ──")
carol_copy = os.path.join(root, "carol-copy.db")
shutil.copy(cp.store.db_path, carol_copy)   # state BEFORE removal
e, _ = G["alice-phone"].remove(gid, [f"carol/{cp.device_id}"])
print(
    f"  remove commit merged at epoch {e}; carol's phone receives: "
    f"{G['carol-phone'].receive()}")
for n in G:
    if n != "carol-phone": G[n].receive()
st, size = G["alice-tablet"].send(gid, "after carol left")
# take the ciphertext the DS fanned out
st2, q = bi.call("GET", "/v1/messages")
ct_after = __import__("murmur_pb2").Envelope.FromString(unb64(
    q["envelopes"][-1]["body"])).content
try: G["carol-phone"].core.process(ct_after)
except mg.GroupError as e:
    print(
        f"  carol's phone is handed the next message anyway: refused "
        f"({e.__class__.__name__}: the group is gone from her device)")
print(
    f"  carol's queue after removal: "
    f"{len(cp.call('GET', '/v1/messages')[1]['envelopes'])} envelopes (the "
    f"DS no longer routes to her)")

print(
    "── 7. Bob loses his iPad: revoke, new device list, removed from EVERY "
    "group by his iPhone ──")
bi.login(phr=True)
bi.call("POST", "/v1/devices/revoke", {"device": bp.device_id})
publish(bi, "bob", [bi], 2)
for n, m in M.items():
    if n != "bob-ipad": m.refresh_contact("bob")
for g in G["bob-iphone"].core.group_ids():
    e, _ = G["bob-iphone"].remove(g, [f"bob/{bp.device_id}"])
    print(
        f"  group {g.hex()[:8]}…: bob's iPhone (not an admin) removes his "
        f"own lost iPad → epoch {e}")
for n in ("alice-phone", "alice-tablet"):
    print(f"  {n:<13} sees: {[r for r in G[n].receive() if r[0] == 'commit']}")
st, _ = G["alice-phone"].send(gid, "the iPad is gone")
try:
    G["bob-ipad"].core.process(G["alice-phone"].core.encrypt(gid,
        b"a copy handed to the thief"))
except mg.GroupError as e:
    print(
        f"  the lost iPad's state, given a new message: cannot decrypt "
        f"({getattr(e, 'msg', e)})")

print("── 8. Bob's replacement iPad is added to every group by his iPhone ──")
bp2 = device("bob", "ios", "bob-ipad-2", aik_of(bi))
publish(bi, "bob", [bi, bp2], 3)
for m in [x for n, x in M.items() if n != "bob-ipad"] + [bp2]:
    for acct in ("alice", "bob", "carol"): m.refresh_contact(acct)
G["bob-ipad-2"] = GroupService(bp2)
M["bob-ipad-2"] = bp2
G["bob-ipad-2"].publish_key_packages(3)
for g in G["bob-iphone"].core.group_ids():
    e, _ = G["bob-iphone"].add_devices(g, [bp2.device_id])
    print(f"  group {g.hex()[:8]}…: bob's iPhone adds his new iPad → epoch {e}")
print(f"  new iPad: {G['bob-ipad-2'].receive()}")
for n in ("alice-phone", "alice-tablet", "bob-iphone"): G[n].receive()
G["alice-phone"].send(gid, "welcome, new iPad")
print(
    f"  new iPad decrypts: "
    f"{[r[2] for r in G['bob-ipad-2'].receive() if r[0] == 'message']}  "
    f"(history before it joined: none — by design)")

print(
    "── 9. Post-compromise security: Alice's tablet state is copied, then "
    "the tablet updates ──")
stolen = os.path.join(root, "tablet-stolen.db")
shutil.copy(at.store.db_path, stolen)
for s in ("-wal", "-shm"):
    if os.path.exists(at.store.db_path + s):
        shutil.copy(at.store.db_path + s, stolen + s)
import sqlcipher3
from device_store import HardwareKeyStandIn, DB_KEY_LABEL
k = HardwareKeyStandIn(os.path.join(root, "alice-tablet", "hardware"),
    "murmur.db.wrap").unwrap(
    open(os.path.join(root, "alice-tablet", "app", "dbkey.wrapped"),
    "rb").read(), DB_KEY_LABEL)
sdb = sqlcipher3.connect(stolen, isolation_level=None)
sdb.execute(f"PRAGMA key = \"x'{k.hex()}'\"")
thief = mg.MurmurGroups.open("alice", at.device_id, SqlCipherMlsStore(sdb),
    VerifiedDirectory(at), mg.CredentialBinder())
m1 = G["bob-iphone"].core.encrypt(gid, b"before the update")
print(
    f"  the thief's copy decrypts a current message: "
    f"{thief.process(m1).plaintext}")
G["alice-tablet"].receive()
# fresh leaf secret, new path
upd = G["alice-tablet"].core.self_update(gid)
members = [x.split("/", 1)[1] for x in G["alice-tablet"].core.members(gid)]
st, _ = at.call("POST", "/v1/groups/commit", {"message": b64(upd.commit),
    "members": members, "joiners": []})
e = G["alice-tablet"].core.merge_pending(gid)
print(f"  the tablet commits a self-update → {st}, epoch {e}")
try: thief.process(upd.commit); print("  thief processed the update (!)")
except mg.GroupError as err:
    print(
        f"  thief, given the update commit itself: cannot process it "
        f"({getattr(err, 'msg', err)})")
for n in G:
    if n not in ("alice-tablet", "carol-phone", "bob-ipad"): G[n].receive()
m2 = G["bob-iphone"].core.encrypt(gid, b"after the update")
try: print(f"  thief, next message: {thief.process(m2)}")
except mg.GroupError as e:
    print(
        f"  thief, next message: cannot decrypt — the update healed the "
        f"group ({getattr(e, 'msg', e)})")

print(
    "── 10. Bob leaves: his iPhone removes his iPad, proposes its own "
    "removal; Alice commits ──")
G["bob-iphone"].remove(gid, [f"bob/{bp2.device_id}"])
for n in ("alice-phone", "alice-tablet", "bob-ipad-2"): G[n].receive()
print(
    f"  leave proposal → {G['bob-iphone'].leave(gid)}; alice's phone: "
    f"{[r for r in G['alice-phone'].receive() if r[0] == 'proposal']}")
e, _ = G["alice-phone"].commit_proposals(gid, [f"bob/{bi.device_id}"])
print(
    f"  alice commits it → epoch {e}; bob's iPhone: "
    f"{G['bob-iphone'].receive()}")
G["alice-tablet"].receive()
same = G['alice-phone'].safety_code(gid) == G['alice-tablet'].safety_code(gid)
print(f"  members now: {G['alice-phone'].core.members(gid)}; "
      f"safety codes match: "
      f"{same}")

srv.terminate(); srv.wait()
print("── 11. What the server stored ──")
dump = open(os.path.join(lab, "store-dump.bin"), "rb").read()
for needle in (b"the eagle lands at nine", b"hello from carol",
    b"after carol left", b"welcome, new iPad"):
    print(
        f"  {needle.decode()!r:<28} in any byte the server stored: "
        f"{'FOUND (!)' if needle in dump else 'absent'}")
