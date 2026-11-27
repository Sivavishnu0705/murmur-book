# lab.py
"""Listing 28.15 — Python: lab driver — two devices registered. An "Android"
device for Alice and an "iOS" device for Bob enroll, generate and store their
keys in the SQLCipher model, upload them, verify each other's bundles, exchange
a first message, keep prekeys stocked for five simulated weeks, retry safely,
and finally have their local storage inspected and wiped."""
import glob, json, os, random, sqlite3, subprocess, sys, tempfile, atexit, time
HERE = os.path.dirname(os.path.abspath(__file__))
BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch26code/spec", "ch27code/lab"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import xeddsa
from murmur_client import Edge, Device, encode_device_list, b64, unb64
from stored_device import StoredDevice, DAY

root = tempfile.mkdtemp(prefix="murmur28-")
srv = subprocess.Popen([sys.argv[1], "-out", os.path.join(root, "server")],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
atexit.register(srv.kill)
assert srv.stdout.readline().strip() == "ready"
edge = Edge(os.path.join(root, "server"), json.load(open(os.path.join(root,
    "server", "ready.json"))))
attest = ser.load_pem_private_key(open(os.path.join(root, "server",
    "lab-attestation-key.pem"), "rb").read(), None)
APPS = {"android": "example.murmur:SHA256:8F:1C:…",
    "ios": "TEAMID1234.example.murmur"}
T0 = time.time()

print("── 1. Enroll, generate, store, upload ──")
alice = StoredDevice(edge, "alice", "android", APPS["android"], attest,
    os.path.join(root, "alice-pixel"), "fcm-a")
bob = StoredDevice(edge, "bob", "ios", APPS["ios"], attest, os.path.join(root,
    "bob-iphone"), "apns-b")
for d in (alice, bob):
    st, js = d.login(phr=True)
    # stand-in; DPoP-bound in Ch 15
    d.store.put_token("refresh_token_family", "rt-" + os.urandom(8).hex())
    d.create_identity()
    st1, st2 = d.register_keys(T0)
    aik_pub, aik_priv = d.store.identity("account_identity")
    aik = Ed25519PrivateKey.from_private_bytes(aik_priv)
    d.call("PUT", "/v1/aik", {"aik": b64(aik_pub)})
    enc = encode_device_list(d.account, 1, [{"id": d.device_id, "ik": d.ik.pub,
        "name": d.platform, "added": int(T0)}])
    st3, _ = d.call("PUT", "/v1/devicelist", {"encoded": b64(enc),
        "signature": b64(aik.sign(enc))})
    d.aik_pub = aik_pub
    print(
        f"  {d.account}/{d.platform:<7} {d.device_id}: identity {st1}, "
        f"prekeys {st2}, device list {st3}; stored locally: "
        f"{d.store.count('opk')} OPK, {d.store.count('pqopk')} PQ OPK, "
        f"{d.store.count('spk')} SPK, {d.store.count('pqlr')} PQ last-resort")

print("── 2. Verify each other's bundles ──")
for me, peer in ((alice, bob), (bob, alice)):
    st, dl = me.call("GET", f"/v1/devicelist/{peer.account}")
    # AIK: first contact + KT (Ch 20)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(peer.aik_pub).verify(unb64(
        dl["signature"]), unb64(dl["encoded"]))
    st, b = me.call("GET", f"/v1/keys/bundle/{peer.device_id}")
    ik, spk, pq = unb64(b["identity_key"]), unb64(
        b["signed_prekey"]["pub"]), unb64(b["pq_prekey"]["pub"])
    ok = (ik in unb64(dl["encoded"]) and xeddsa.verify(ik, b"\x05" + spk,
        unb64(b["signed_prekey"]["sig"]))
        and xeddsa.verify(ik, b"\x08" + pq, unb64(b["pq_prekey"]["sig"])))
    print(
        f"  {me.account} checks {peer.account}'s bundle: IK in signed device "
        f"list, SPK and PQ signatures valid: {ok} "
        f"(OPK {b['one_time_prekey']['id']}, PQ OPK {b['pq_prekey']['id']}, "
        f"{len(json.dumps(b))} B JSON)")
    if me is alice: bundle_for_bob = b
for d in (alice, bob):
    st, c = d.call("GET", "/v1/keys/count")
    print(f"  server count for {d.account}: {c}")

print(
    "── 3. First message: Bob's private prekeys come out of the encrypted "
    "store ──")
env = alice.start_session(bob.device_id, bundle_for_bob,
    b"hello from the pixel")
alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [{"device": bob.device_id, "body": b64(env)}]})
st, q = bob.call("GET", "/v1/messages"); x = q["envelopes"][0]
opk_id = bundle_for_bob["one_time_prekey"]["id"]
print(
    f"  bob holds OPK {opk_id} before: "
    f"{bob.store.get('opk', opk_id) is not None}")
pt = bob.decrypt(unb64(x['body']), alice.device_id)
pq_id = bundle_for_bob['pq_prekey']['id']
print(f"  bob decrypts: {pt!r}; OPK {opk_id} and PQ OPK "
      f"{pq_id} still stored: {bob.store.get('opk', opk_id) is not None}, "
      f"{bob.store.get('pqopk', pq_id) is not None}")
bob.call("POST", "/v1/messages/ack", {"guids": [x["guid"]]})

print("── 4. Retries and idempotency keys ──")
ec, pq = alice._new_one_time(3, 0, T0)
before = alice.call("GET", "/v1/keys/count")[1]["one_time"]
st, js = alice.call("PUT", "/v1/keys/prekeys", {"one_time": ec},
    lose_first_response=True)
after = alice.call("GET", "/v1/keys/count")[1]["one_time"]
print(
    f"  upload 3 OPKs, first response lost, retried with the same key → {st} "
    f"{js}; server OPKs {before} → {after}")
key = "6f1c3a2e-0b7d-4d1e-9c55-2f8e7a1d4b90"
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [{"device": bob.device_id,
                   "body": b64(alice.encrypt(bob.device_id, b"once"))}]},
                   idem=key, lose_first_response=True)
print(
    f"  send a message, first response lost, retried with the same key → "
    f"{st} {js}")
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [{"device": bob.device_id, "body": b64(b"different")}]},
    idem=key)
print(f"  same Idempotency-Key, different body → {st} {js}")
st, js, _ = edge.request("api", "PUT", "/v1/keys/prekeys", {"one_time": []},
    {"Authorization": "DPoP " + alice.token,
        "DPoP": alice.proof("PUT", "https://api.murmur.test/v1/keys/prekeys",
        alice.token)})
print(f"  state-changing request without an Idempotency-Key → {st} {js}")
st, q = bob.call("GET", "/v1/messages")
print(
    f"  bob's queue: {len(q['envelopes'])} envelope(s) — the message, "
    f"delivered once")
bob.call("POST", "/v1/messages/ack",
    {"guids": [e["guid"] for e in q["envelopes"]]})

print(
    "── 5. Six simulated weeks of prekey maintenance on Bob's phone (daily "
    "job) ──")
contacts = []
for i in range(16):
    c = Device(edge, f"contact{i}", "android", APPS["android"], attest)
    c.login()
    contacts.append(c)
random.seed(28); fetched = 0; rr = 0; purged = 0
print("  day  fetched  server OPK/PQ before job   job did")
for day in range(1, 43):
    # other people start sessions with Bob
    for _ in range(random.choice([0, 1, 2, 3, 4, 6, 8, 9])):
        contacts[rr % len(contacts)].call("GET",
            f"/v1/keys/bundle/{bob.device_id}")
        rr += 1
        fetched += 1
    c = bob.call("GET", "/v1/keys/count")[1]
    did = bob.maintain(T0 + day * DAY)
    purged += sum(int(x.split()[1]) for x in did if x.startswith("deleted"))
    did = [x for x in did if not x.startswith("deleted")]
    # print uploads, rotations and each week
    if did or day % 7 == 0:
        if purged:
            did.append(
                f"deleted {purged} expired private key(s) since last row")
            purged = 0
        print(
            f"  {day:>3}  {fetched:>7}  "
            f"{c['one_time']:>3}/{c['pq_one_time']:<3}                    "
            f"{', '.join(did) or '—'}")
sid, _ = bob.store.current_signed("spk")
print(
    f"  after 42 days: current SPK {sid}; SPK private keys held (current + "
    f"replaced < 30 days ago): {bob.store.count('spk')}; "
    f"OPK private keys held locally {bob.store.count('opk')} (on the server "
    f"or handed out < 30 days ago); server "
    f"{bob.call('GET', '/v1/keys/count')[1]}")

print("── 6. Inspect local encrypted storage ──")
for d in (alice, bob):
    files = sorted(os.path.relpath(p,
        os.path.dirname(d.store.app_dir)) for p in glob.glob(os.path.join(
        os.path.dirname(d.store.app_dir), "*", "*")))
    print(f"  {d.account}: {', '.join(files)}")
db = bob.store.db_path
print(
    f"  core.db header: {open(db, 'rb').read(16).hex()}  (a plain SQLite "
    f"file starts with {b'SQLite format 3'.hex()}00)")
try:
    sqlite3.connect(db).execute("SELECT count(*) FROM sqlite_master").fetchone()
    print("  plain sqlite3 opened it (!)")
except sqlite3.DatabaseError as e:
    print(f"  plain sqlite3: {e}")
# core.db, -wal, -shm
blob = b"".join(open(p, "rb").read() for p in glob.glob(db + "*"))
pub_ik, priv_ik = bob.store.identity("device_identity")
spk_priv = bob.store.get("spk", sid)
row = bob.store.db.execute("SELECT wrapped_priv FROM identity WHERE "
    "name='device_identity'").fetchone()[0]
checks = {"identity private key (raw)": priv_ik, "identity public key": pub_ik,
    "current SPK private key": spk_priv,
    "refresh token": bob.store.db.execute(
    "SELECT value FROM session_tokens").fetchone()[0].encode(),
    "table name 'prekeys'": b"prekeys"}
for k, v in checks.items():
    print(
        f"  {k:<30} in core.db / -wal / -shm bytes: "
        f"{'FOUND (!)' if v in blob else 'absent'}")
print(
    f"  inside the database (opened with the unwrapped key) the identity "
    f"private key column holds "
    f"{len(row)} B of AES-GCM ciphertext, not the 32-byte key: "
    f"{row != priv_ik and len(row) == 12 + 32 + 16}")

print("── 7. Wipe on remote revocation: key first, then files ──")
other = StoredDevice(edge, "bob", "ios", APPS["ios"], attest, os.path.join(root,
    "bob-ipad"), "apns-b2")
other.login(phr=True)
st, _ = other.call("POST", "/v1/devices/revoke", {"device": bob.device_id})
st2, js = bob.call("GET", "/v1/messages")
print(
    f"  bob's iPad revokes the iPhone → {st}; the iPhone's next call → {st2} "
    f"({js.get('www_authenticate', '')[:60]}…)")
print(
    "  the iPhone wipes; the app is killed right after the hardware key is "
    "deleted, before any file is removed")
bob.store.wipe(crash_after_key=True)
left = sorted(os.path.basename(p) for p in glob.glob(os.path.join(
    bob.store.app_dir, "*")))
print(f"  files left behind: {left}")
try:
    from device_store import DeviceStore
    DeviceStore(bob.store.app_dir, os.path.join(root, "bob-iphone", "hardware"))
except Exception as e:
    print(
        f"  reopening the database: {type(e).__name__} — the wrapped "
        f"database key no longer unwraps")
__import__("shutil").rmtree(bob.store.app_dir)
print(
    f"  the next launch finds no usable key and deletes the leftovers; app "
    f"directory exists: {os.path.exists(bob.store.app_dir)}")
