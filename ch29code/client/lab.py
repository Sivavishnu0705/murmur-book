# lab.py
"""Listing 29.13 — Python: lab driver — a cross-platform conversation. Alice (Android phone +
Android tablet) and Bob (iPhone) talk through the Chapter 27–29 server with sealed sender,
fan-out and sync, attachments, offline periods and out-of-order delivery, crashes at every
point of both pipelines, an NSE racing the app, a lost session and its reset, clock skew, a
mid-send device change, and finally a reinstall that produces a key-change warning."""
import io, json, os, random, shutil, subprocess, sys, tempfile, time, tracemalloc, atexit
HERE = os.path.dirname(os.path.abspath(__file__)); BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch20code", "ch21code/attach", "ch29code/spec", "ch27code/lab", "ch28code/client"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import safety, murmur_pb2 as pb
from murmur_client import Edge, encode_device_list, b64, unb64
from messenger import Messenger, Edge29, Crash, KeyChangeBlocked, export_device
import attach_client as att

root = tempfile.mkdtemp(prefix="murmur29-"); lab = os.path.join(root, "server")
srv = subprocess.Popen([sys.argv[1], "-out", lab], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
atexit.register(srv.kill)
assert srv.stdout.readline().strip() == "ready"
edge = Edge29(Edge(lab, json.load(open(os.path.join(lab, "ready.json")))))
attest = ser.load_pem_private_key(open(os.path.join(lab, "lab-attestation-key.pem"), "rb").read(), None)
cert_pub = ser.load_pem_public_key(open(os.path.join(lab, "sender-cert-key.pub"), "rb").read())
APPS = {"android": "example.murmur:SHA256:8F:1C:…", "ios": "TEAMID1234.example.murmur"}
T0 = time.time()

def device(account, platform, name, aik=None, first=True):
    m = Messenger(edge, account, platform, APPS[platform], attest, os.path.join(root, name), "push-" + name, cert_pub=cert_pub)
    m.login(phr=True)
    m.create_identity()
    if aik is not None:                                   # linked device: the AIK came over the Noise pairing
        m.store.db.execute("DELETE FROM identity WHERE name='account_identity'")
        from cryptography.hazmat.primitives import serialization as s2
        m.store.put_identity("account_identity", aik.public_key().public_bytes_raw(),
                             aik.private_bytes(s2.Encoding.Raw, s2.PrivateFormat.Raw, s2.NoEncryption()))
    m.register_keys(T0)
    return m

def aik_of(m): return Ed25519PrivateKey.from_private_bytes(m.store.identity("account_identity")[1])

def publish_list(signer, account, devices, version):
    enc = encode_device_list(account, version, [{"id": d.device_id, "ik": d.ik.pub, "name": d.platform, "added": 1} for d in devices])
    return signer.call("PUT", "/v1/devicelist", {"encoded": b64(enc), "signature": b64(aik_of(signer).sign(enc))})[0]

print("── 1. Devices ──")
alice = device("alice", "android", "alice-phone")
alice.call("PUT", "/v1/aik", {"aik": b64(aik_of(alice).public_key().public_bytes_raw())})
publish_list(alice, "alice", [alice], 1)
tablet = device("alice", "android", "alice-tablet", aik=aik_of(alice))
publish_list(alice, "alice", [alice, tablet], 2)          # the phone approves the tablet (Ch 20 §20.2)
bob = device("bob", "ios", "bob-iphone")
bob.call("PUT", "/v1/aik", {"aik": b64(aik_of(bob).public_key().public_bytes_raw())})
publish_list(bob, "bob", [bob], 1)
for d in (alice, tablet, bob): d.call("PUT", "/v1/delivery-token", {"token": b64(d.token_for_replies)})
# Devices of one account share the account's delivery token in production; here each sets its own,
# and the last one set wins for the account — so give all of Alice's devices the phone's token.
tablet.token_for_replies = alice.token_for_replies; alice.call("PUT", "/v1/delivery-token", {"token": b64(alice.token_for_replies)})
print(f"  alice: phone {alice.device_id}, tablet {tablet.device_id} (device list v2)   bob: iPhone {bob.device_id}")

print("── 2. Safety numbers and verification ──")
for m, other in ((alice, "bob"), (bob, "alice"), (tablet, "bob")): m.refresh_contact(other)
sn_a, sn_b = alice.safety_number("bob"), bob.safety_number("alice")
print(f"  alice sees {safety.pretty(sn_a)}\n  bob sees   {safety.pretty(sn_b)}   same: {sn_a == sn_b}")
print(f"  alice scans the QR code on bob's screen: verified = {alice.scan_qr('bob', bob.qr('alice'))}; trust: {alice.trust('bob')}")
SN_BEFORE = sn_a

print("── 3. Conversation: first contact, sealed replies, fan-out and sync ──")
cmid, res = alice.send("bob", "hi Bob — the eagle lands at nine")
print(f"  alice → bob (first contact, PreKeyMessage): {res}")
for r in bob.receive(): print(f"  bob: {r}")
cmid, res = bob.send("alice", "hi Alice!")
print(f"  bob → alice: {res}   (route 'sealed': bob learned alice's delivery token from her message)")
for who, d in (("alice phone", alice), ("alice tablet", tablet)):
    for r in d.receive(): print(f"  {who}: {r}")
cmid, res = alice.send("bob", "lunch tomorrow?")
print(f"  alice → bob: {res}   (second row: the sync copy to her tablet)")
bob.receive(); print(f"  alice tablet: {tablet.receive()}")

print("── 4. Offline period and out-of-order processing ──")
for i in range(12): alice.send("bob", f"offline message {i + 1}")
random.seed(29)
got = bob.receive(order=lambda e: random.sample(e, len(e)))
print(f"  bob was offline for 12 messages; processed them in shuffled order: all decrypted = "
      f"{sorted(r[3] for r in got) == sorted(f'offline message {i + 1}' for i in range(12))} ({len(got)})")
tablet.receive()

print("── 5. Persistence ordering: crash at every point ──")
def inbox_count(m, text): return m.store.db.execute("SELECT count(*) FROM inbox WHERE text=? AND outgoing=0", (text,)).fetchone()[0]
alice.send("bob", "crash test R1")
try: bob.receive(crash="after_decrypt_before_commit")
except Crash as e: print(f"  receive, crash {e}: rolled back; relay redelivers → {bob.receive()}; stored {inbox_count(bob, 'crash test R1')}×")
alice.send("bob", "crash test R2")
try: bob.receive(crash="after_commit_before_ack")
except Crash as e: print(f"  receive, crash {e}: redelivered → {bob.receive() or 'recognized as processed, acked'}; stored {inbox_count(bob, 'crash test R2')}×")
try: alice.send("bob", "crash test S1", crash="after_encrypt_before_commit")
except Crash as e:
    print(f"  send, crash {e}: nothing persisted, nothing sent; outbox rows: {alice.store.db.execute('SELECT count(*) FROM outbox').fetchone()[0]}")
try: alice.send("bob", "crash test S2", crash="after_commit_before_send")
except Crash as e:
    print(f"  send, crash {e}: outbox rows after restart: {alice.store.db.execute('SELECT count(*) FROM outbox').fetchone()[0]} → flush {alice.flush_outbox()}")
r = bob.receive(); print(f"  bob receives {[x[3] for x in r]}, each once")
tablet.receive()
# ⚠️ INSECURE: send BEFORE persisting the advanced state; the app is killed; the next message reuses the key
from messenger import load_state, dump_state
from murmur_client import pad
peer = alice.peer_key("bob", bob.device_id)
st_, ad = alice.store.db.execute("SELECT state, ad FROM sessions WHERE peer=?", (peer,)).fetchone()[:2]
r1 = load_state(st_); h1, c1 = r1.encrypt(pad(b"PIN is 4321"), ad)               # sent… then the app dies
r2 = load_state(st_); h2, c2 = r2.encrypt(pad(b"see you at 6"), ad)              # restart: same state
xc = bytes(a ^ b for a, b in zip(c1, c2))
xp = bytes(a ^ b for a, b in zip(pad(b"PIN is 4321"), pad(b"see you at 6")))
print(f"  ⚠️ naive send (network before persist), app killed: same header reused: {h1 == h2}; "
      f"ct1 ⊕ ct2 = pt1 ⊕ pt2 (same key, same nonce): {xc[:len(xp)] == xp}")
print(f"     anyone who knows one message learns the other: {bytes(a ^ b for a, b in zip(xc, pad(b'see you at 6')))[:11]!r}")

print("── 6. The NSE and the app on the same database at the same moment ──")
state = os.path.join(root, "bob-shared.json"); export_device(bob, state)
for mode in ("canonical", "naive"):
    for i in range(15): alice.send("bob", f"{mode} {i + 1}")
    start = time.time() + 1.5
    procs = [subprocess.Popen([sys.executable, os.path.join(HERE, "nse.py"), state, lab, mode, str(start), w],
                              stdout=subprocess.PIPE, text=True) for w in ("app", "nse")]
    outs = [json.loads(p.communicate()[0]) for p in procs]
    a, n = set(outs[0]["decrypted"]), set(outs[1]["decrypted"])
    nr = json.loads(bob.store.db.execute("SELECT state FROM sessions WHERE peer=?", (bob.peer_key("alice", alice.device_id),)).fetchone()[0])["Nr"]
    print(f"  {mode:<9}: app decrypted {len(a)}, NSE decrypted {len(n)}, BOTH decrypted {len(a & n)}; "
          f"stored ratchet Nr = {nr}")
    tablet.receive()
    if mode == "canonical": nr_canonical = nr

print("── 7. Attachments ──")
src = os.path.join(root, "photo.bin")
with open(src, "wb") as f: f.write(os.urandom(3 * 1024 * 1024 - 777) + b"the eagle lands at nine")
blob = os.path.join(root, "photo.enc")
key, digest, size = att.encrypt_file(src, blob)
cdn_id, resumed_at, reqs = att.upload(alice, blob, size, drop_after=4)
print(f"  encrypted {os.path.getsize(src)} B → {size} B; upload dropped after 4 requests, resumed at offset {resumed_at}; "
      f"{reqs} requests in all")
alice.send("bob", "photo", attachments=[att.pointer(cdn_id, key, digest, size, "image/jpeg")])
bob.receive(); tablet.receive(); ptr = bob.last_attachments[0]
tracemalloc.start()
res = att.download(bob, ptr, os.path.join(root, "bob-photo.jpg"))
peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
same = open(os.path.join(root, "bob-photo.jpg"), "rb").read() == open(src, "rb").read()
print(f"  bob downloads: {res}, identical: {same}, peak Python memory {peak // 1024} KiB for a {size // 1024} KiB file")
print(f"  NSE preview (1 MiB budget): {att.download(bob, ptr, os.path.join(root, 'nse.jpg'), max_size=1 << 20)}")
print(f"  a byte changed on the CDN: {att.download(bob, ptr, os.path.join(root, 't1.jpg'), tamper=True)}")
print(f"  …even with the digest check skipped: {att.download(bob, ptr, os.path.join(root, 't2.jpg'), tamper='skip-digest-check')}; "
      f"plaintext file exists: {os.path.exists(os.path.join(root, 't2.jpg'))}")

print("── 8. Bob's device set changes while Alice is sending ──")
ipad = device("bob", "ios", "bob-ipad", aik=aik_of(bob))
publish_list(bob, "bob", [bob, ipad], 2)
ipad.call("PUT", "/v1/delivery-token", {"token": b64(bob.token_for_replies)}); ipad.token_for_replies = bob.token_for_replies
cmid, res = alice.send("bob", "are you on your iPad?")
print(f"  alice's send (she only knew the iPhone): {res}; repairs (removed, added): {alice.fanout_repairs}")
print(f"  iPhone: {[r[3] for r in bob.receive()]}   iPad: {[r[3] for r in ipad.receive()]}"); tablet.receive()
bob.login(phr=True); bob.call("POST", "/v1/devices/revoke", {"device": ipad.device_id}); publish_list(bob, "bob", [bob], 3)

print("── 9. Errors and recovery ──")
bob.store.db.execute("DELETE FROM sessions WHERE peer=?", (bob.peer_key("alice", alice.device_id),))   # a bug loses the session
bob.store.db.execute("DELETE FROM archived_sessions")
alice.send("bob", "did you get this?")
print(f"  bob lost his session with alice's phone; next message: {bob.receive()}")
print(f"  alice receives bob's new session: {alice.receive()}; re-sends {alice.handle_resends()} message(s) from her 24 h send log")
print(f"  bob: {bob.receive()}"); tablet.receive()
# A replay: the same sealed envelope posted again (new GUID at the relay)
captured = {}
orig = bob.edge.request
def capture(*a, **kw):
    st, js, h = orig(*a, **kw)
    if a[1] == "GET" and a[2] == "/v1/messages" and js.get("envelopes"): captured["e"] = js["envelopes"][0]["body"]
    return st, js, h
bob.edge.request = capture
alice.send("bob", "original"); bob.receive(); bob.edge.request = orig; tablet.receive()
edge.request("api", "POST", "/v1/sealed", {"recipient_account": "bob", "envelopes": [{"device": bob.device_id, "body": captured["e"]}]},
             {"Murmur-Delivery-Token": b64(bob.token_for_replies)})
print(f"  the same envelope delivered again: {bob.receive()}")
alice.clock_offset = 600                                 # alice's clock is 10 minutes fast
st, js = alice.call("GET", "/v1/messages")
print(f"  alice's clock 10 min fast: first DPoP proof rejected; offset re-learned from the Date header "
      f"(now {alice.clock_offset:+.0f} s, 1-second resolution), retried → {st}")

# A device that enrolled for alice's account but that her AIK never approved (for example one the
# server invented, since the server signs sender certificates): its messages must be refused.
rogue = device("alice", "android", "alice-unlisted")
rogue.refresh_contact("bob"); rogue.refresh_contact("alice")
rogue.send("bob", "it's really me, Alice")
print(f"  a valid sender certificate from a device NOT in alice's signed list → bob: {bob.receive()}")
alice.login(phr=True); alice.call("POST", "/v1/devices/revoke", {"device": rogue.device_id}); tablet.receive(); alice.receive()

print("── 10. Bob reinstalls: a key change Alice can see ──")
bob.store.wipe()                                          # app deleted: keys and files gone, nothing in backups
bob2 = device("bob", "ios", "bob-iphone-reinstalled")    # enrolls again with step-up
bob2.call("POST", "/v1/devices/revoke", {"device": bob.device_id})   # "lost device" flow in the new install
print(f"  new install {bob2.device_id}: AIK replaced → {bob2.call('PUT', '/v1/aik', {'aik': b64(aik_of(bob2).public_key().public_bytes_raw())})[0]}; "
      f"device list v4 → {publish_list(bob2, 'bob', [bob2], 4)}")
bob2.call("PUT", "/v1/delivery-token", {"token": b64(bob2.token_for_replies)})
try:
    alice.send("bob", "still there?")                    # mismatch → refresh → the AIK changed
except KeyChangeBlocked as e:
    print(f"  alice's send is blocked: {e}")
sn_after = alice.safety_number("bob")
print(f"  trust: {alice.trust('bob')}\n  safety number before: {safety.pretty(SN_BEFORE)}\n  safety number now:    {safety.pretty(sn_after)}")
bob2.refresh_contact("alice")
print(f"  alice and bob compare in person; alice scans bob's new QR: {alice.scan_qr('bob', bob2.qr('alice'))}; trust: {alice.trust('bob')}")
cmid, res = alice.send("bob", "welcome back"); print(f"  alice → bob: {res}; bob: {[r[3] for r in bob2.receive()]}")

srv.terminate(); srv.wait()
print("── 11. What the server and the push providers saw ──")
dump = open(os.path.join(lab, "store-dump.bin"), "rb").read()
for needle in (b"the eagle lands at nine", b"lunch tomorrow", b"offline message", b"did you get this?"):
    print(f"  {needle.decode()!r:<28} in any byte the server stored: {'FOUND (!)' if needle in dump else 'absent'}")
pushes = open(os.path.join(lab, "push-providers.log")).read().splitlines()
import re
shapes = sorted({re.sub(r'"token":"[^"]*"', '"token":"…"', l.split("payload=")[1]) for l in pushes if "payload=" in l})
print(f"  push requests: {len(pushes)}; distinct payloads (device token elided):")
for p in shapes: print(f"    {p}")
