# lab.py
"""Listing 27.14 — Python: lab driver — end-to-end server integration tests.
Starts the Go server, then scripted clients register, upload keys, run PQXDH,
exchange Double Ratchet messages through the relay, and probe every server-side
check from this chapter."""
import base64, io, json, os, subprocess, sys, tempfile, threading, time, atexit
HERE = os.path.dirname(os.path.abspath(__file__))
BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch21code/attach", "ch26code/spec"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import attachments, murmur_pb2 as pb
from murmur_client import Edge, Device, encode_device_list, b64, unb64

lab = tempfile.mkdtemp(prefix="murmur-lab-")
srv = subprocess.Popen([sys.argv[1], "-out", lab], stdout=subprocess.PIPE,
    stderr=open(os.path.join(lab, "stderr.log"), "w"), text=True)
atexit.register(srv.kill)
assert srv.stdout.readline().strip() == "ready"
edge = Edge(lab, json.load(open(os.path.join(lab, "ready.json"))))
attest = ser.load_pem_private_key(open(os.path.join(lab,
    "lab-attestation-key.pem"), "rb").read(), None)
A_APP, I_APP = "example.murmur:SHA256:8F:1C:…", "TEAMID1234.example.murmur"
CANARY = b"the eagle lands at nine"
show = lambda label, st, js=None: print(
    f"  {label:<58} → {st} "
    f"{json.dumps(js, separators=(',', ':')) if js else ''}"[:180])
code = lambda js: js.get("code", js)

print("── 1. Enrollment (attestation + proof of possession + DPoP key) ──")
alice = Device(edge, "alice", "android", A_APP, attest,
    push_token="fcm-token-alice")
bob = Device(edge, "bob", "ios", I_APP, attest, push_token="apns-token-bob")
carol = Device(edge, "carol", "ios", I_APP, attest, push_token="dead-token")
mallory = Device(edge, "mallory", "android", A_APP, attest)
for d in (alice, bob, carol, mallory):
    st, js = d.login()
    print(
        f"  {d.account:<8} enrolled: {d.device_id}  ({d.platform}, token "
        f"{js['token_type']}, {js['expires_in']} s)")
eve = Device(edge, "eve", "android", A_APP, attest)
st, js = eve.login(reuse_nonce=alice.last_nonce)
show("enroll with an already-used nonce", st, js)
st, js = eve.login(app_id="com.repackaged.murmur")
show("enroll from a repackaged app (wrong AppID)", st, js)

print("── 2. Key directory uploads ──")
for d in (alice, bob, carol):
    st1, st2 = d.upload_keys()
show("bob: identity key, SPK, PQ last-resort, 5 OPKs, 2 PQ OPKs",
    f"{st1} / {st2}")
st, js = bob.call("POST", "/v1/keys/identity",
    {"identity_key": b64(os.urandom(32))})
show("bob: replace identity key", st, js)
bad = {"signed_prekey": {"id": 2, "pub": b64(os.urandom(32)),
    "sig": b64(os.urandom(64))}}
st, js = bob.call("PUT", "/v1/keys/prekeys", bad)
show("bob: SPK with an invalid signature", st, js)
import xeddsa
pq = bob.pq_last.public_key().public_bytes_raw()
wrongtype = {"pq_one_time": [{"id": 300, "pub": b64(pq),
    "sig": b64(xeddsa.sign(bob.ik.priv, b"\x05" + pq))}]}
st, js = bob.call("PUT", "/v1/keys/prekeys", wrongtype)
show("bob: PQ key signed with the EC type byte 0x05", st, js)
aiks = {}
# account identity key + device list v1
for d in (alice, bob):
    aik = Ed25519PrivateKey.generate(); aiks[d.account] = aik
    d.call("PUT", "/v1/aik", {"aik": b64(aik.public_key().public_bytes_raw())})
    enc = encode_device_list(d.account, 1, [{"id": d.device_id, "ik": d.ik.pub,
        "name": "phone", "added": 1}])
    st, js = d.call("PUT", "/v1/devicelist", {"encoded": b64(enc),
        "signature": b64(aik.sign(enc))})
show("alice, bob: AIK-signed device list v1", st, js)
st, js = bob.call("PUT", "/v1/devicelist", {"encoded": b64(enc),
    "signature": b64(aiks["bob"].sign(enc))})
show("bob: re-upload version 1 (rollback)", st, js)

print("── 3. PQXDH + Double Ratchet through the relay ──")
st, bundle = alice.call("GET", f"/v1/keys/bundle/{bob.device_id}")
print(
    f"  alice fetched bob's bundle: OPK {bundle['one_time_prekey']['id']}, "
    f"PQ prekey {bundle['pq_prekey']['id']} "
    f"(last resort: {bundle['pq_last_resort']}); both signatures verify on "
    f"the client")
env = alice.start_session(bob.device_id, bundle, b"hi Bob - " + CANARY)
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [{"device": bob.device_id, "body": b64(env)}]})
show(f"alice → bob: PreKeyMessage envelope, {len(env)} B", st, js)
st, q1 = bob.call("GET", "/v1/messages")
# "crash" before ack: the envelope is still there
st, q2 = bob.call("GET", "/v1/messages")
print(
    f"  bob fetches {len(q1['envelopes'])} envelope; fetches again before "
    f"acking: {len(q2['envelopes'])} (same GUID: "
    f"{q1['envelopes'][0]['guid'] == q2['envelopes'][0]['guid']})")
pt = bob.decrypt(unb64(q1["envelopes"][0]["body"]), alice.device_id)
print(f"  bob decrypts: {pt!r}")
st, js = mallory.call("POST", "/v1/messages/ack",
    {"guids": [q1["envelopes"][0]["guid"]]})
show("mallory acks bob's GUID", st, js)
st, js = bob.call("POST", "/v1/messages/ack",
    {"guids": [q1["envelopes"][0]["guid"]]})
show("bob acks after persisting", st, js)
st, q3 = bob.call("GET", "/v1/messages")
print(f"  bob's queue after ack: {len(q3['envelopes'])} envelopes")
# Bob replies over SEALED SENDER: no Authorization header; the relay checks
# Alice's delivery token.
dtok = os.urandom(16)
alice.call("PUT", "/v1/delivery-token", {"token": b64(dtok)})
inner = bob.encrypt(alice.device_id, b"hi Alice")
eph = X25519PrivateKey.generate()
k = HKDF(hashes.SHA256(), 32, salt=None,
    info=b"murmur sealed sender v1").derive(
    eph.exchange(X25519PublicKey.from_public_bytes(alice.ik.pub)))
# lab: unsigned
cert = pb.SenderCertificate(account="bob", device=bob.device_id,
    identity_key=bob.ik.pub).SerializeToString()
sealed = pb.SealedEnvelope(ephemeral_key=eph.public_key().public_bytes_raw(),
                           ciphertext=AESGCM(k).encrypt(b"\x00" * 12,
                           len(cert).to_bytes(2, "big") + cert + inner, None))
outer = pb.Envelope(version=1, type=pb.SEALED_SENDER,
    recipient_device=alice.device_id,
    content=sealed.SerializeToString()).SerializeToString()
body = {"recipient_account": "alice", "envelopes": [{"device": alice.device_id,
    "body": b64(outer)}]}
st, js, _ = edge.request("api", "POST", "/v1/sealed", body,
    {"Murmur-Delivery-Token": b64(os.urandom(16))})
show("sealed send with a wrong delivery token", st, js)
st, js, _ = edge.request("api", "POST", "/v1/sealed", body,
    {"Murmur-Delivery-Token": "%%not-base64%%"})
show("sealed send with a malformed delivery token", st, js)
st, js, _ = edge.request("api", "POST", "/v1/sealed", body,
    {"Murmur-Delivery-Token": b64(dtok)})
show("sealed send with alice's delivery token (no auth header)", st, js)
st, q = alice.call("GET", "/v1/messages")
e = pb.Envelope.FromString(unb64(q["envelopes"][0]["body"]))
s = pb.SealedEnvelope.FromString(e.content)
k = HKDF(hashes.SHA256(), 32, salt=None,
    info=b"murmur sealed sender v1").derive(
    X25519PrivateKey.from_private_bytes(alice.ik.priv).exchange(
    X25519PublicKey.from_public_bytes(s.ephemeral_key)))
p = AESGCM(k).decrypt(b"\x00" * 12, s.ciphertext, None)
n = int.from_bytes(p[:2], "big")
sender = pb.SenderCertificate.FromString(p[2:2 + n])
print(
    f"  alice unseals: sender {sender.account}/{sender.device}, message "
    f"{alice.decrypt(p[2 + n:], sender.device)!r}")
alice.call("POST", "/v1/messages/ack", {"guids": [q["envelopes"][0]["guid"]]})

print("── 4. Multi-device fan-out ──")
bob2 = Device(edge, "bob", "ios", I_APP, attest,
    push_token="apns-token-bob-ipad")
st, js = bob2.login(phr=False)
show("bob's iPad enrolls without a fresh passkey (step-up)", st, js)
st, js = bob2.login(phr=True)
print(f"  bob's iPad enrolls with step-up: {st} {bob2.device_id}")
bob2.upload_keys()
enc2 = encode_device_list("bob", 2, [{"id": bob.device_id, "ik": bob.ik.pub,
    "name": "phone", "added": 1},
    {"id": bob2.device_id, "ik": bob2.ik.pub, "name": "iPad", "added": 2}])
st, js = bob.call("PUT", "/v1/devicelist", {"encoded": b64(enc2),
    "signature": b64(aiks["bob"].sign(enc2))})
show("bob's phone signs device list v2 (phone + iPad)", st, js)
m1 = alice.encrypt(bob.device_id, b"to bob's devices")
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [{"device": bob.device_id, "body": b64(m1)}]})
show("alice sends to bob's phone only", st, js)
st, dl = alice.call("GET", "/v1/devicelist/bob")
aiks["bob"].public_key().verify(unb64(dl["signature"]), unb64(dl["encoded"]))
print(
    f"  alice fetches bob's device list v2 and verifies the AIK signature; "
    f"then a bundle for the iPad")
st, b2 = alice.call("GET", f"/v1/keys/bundle/{bob2.device_id}")
m2 = alice.start_session(bob2.device_id, b2, b"to bob's devices")
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [
    {"device": bob.device_id, "body": b64(m1)}, {"device": bob2.device_id,
    "body": b64(m2)}]})
show("alice retries to both devices", st, js)
for d in (bob, bob2):
    st, q = d.call("GET", "/v1/messages"); x = q["envelopes"][0]
    print(
        f"  {d.device_id} decrypts "
        f"{d.decrypt(unb64(x['body']), alice.device_id)!r}")
    d.call("POST", "/v1/messages/ack", {"guids": [x["guid"]]})

print("── 5. One-time prekeys under load ──")
seen, got = [], []
for i in range(12):
    st, b = mallory.call("GET", f"/v1/keys/bundle/{carol.device_id}")
    if st != 200: got.append(f"#{i+1}:{st} {code(b)}"); continue
    seen.append((b.get("one_time_prekey") or {}).get("id"))
    lr = '(LR)' if b['pq_last_resort'] else ''
    got.append(f"#{i+1}:OPK={seen[-1]},PQ={b['pq_prekey']['id']}{lr}")
print("  mallory fetches carol's bundle 12 times:")
print("   ", "  ".join(got[:6]))
print("   ", "  ".join(got[6:]))
print(
    f"  distinct OPKs handed out: {len({s for s in seen if s})} of "
    f"{len([s for s in seen if s])} (each at most once)")

print("── 6. Token, DPoP and step-up checks ──")
pr = alice.proof("GET", "https://api.murmur.test/v1/messages", alice.token)
alice.call("GET", "/v1/messages", proof=pr)
st, js = alice.call("GET", "/v1/messages", proof=pr)
show("replayed DPoP proof", st, js.get("www_authenticate"))
st, js = alice.call("GET", "/v1/messages", scheme="Bearer")
show("DPoP-bound token sent as Bearer", st, js.get("www_authenticate"))
st, js = mallory.call("GET", "/v1/messages", token=alice.token)
show("alice's token with mallory's DPoP key", st, js.get("www_authenticate"))
alice.login(phr=False)
st, js = alice.call("PUT", "/v1/aik", {"aik": b64(os.urandom(32))})
show("keys:write with acr=pwd (no recent passkey)", st,
    js.get("www_authenticate"))

print("── 7. Revocation ──")
bob.login(phr=True)
st, js = bob.call("POST", "/v1/devices/revoke", {"device": bob2.device_id})
show("bob's phone revokes the iPad (step-up token)", st, js)
st, js = bob2.call("GET", "/v1/messages")
show("iPad uses its unexpired access token", st, js.get("www_authenticate"))
st, js = alice.call("GET", f"/v1/keys/bundle/{bob2.device_id}")
show("alice fetches the iPad's bundle", st, js)
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "bob",
    "envelopes": [
    {"device": bob.device_id, "body": b64(m1)}, {"device": bob2.device_id,
    "body": b64(m2)}]})
show("alice sends to phone + iPad", st, js)

print("── 8. Offline storage limit and push ──")
res = {}
for i in range(55):
    st, js = alice.call("POST", "/v1/messages", {"recipient_account": "carol",
        "envelopes": [{"device": carol.device_id,
        "body": b64(os.urandom(200))}]})
    res[(st, code(js) if js else "")] = res.get((st, code(js) if js else ""),
        0) + 1
print(
    f"  alice sends 55 opaque test envelopes to offline carol (cap 50): {res}")
carol2 = Device(edge, "carol", "ios", I_APP, attest); carol2.login(phr=True)
st, js = alice.call("POST", "/v1/messages", {"recipient_account": "carol",
    "envelopes": [
    {"device": carol.device_id, "body": b64(os.urandom(200))},
    {"device": carol2.device_id, "body": b64(os.urandom(200))}]})
show("send to carol's full phone + her new, empty tablet", st, js)
st, q = carol2.call("GET", "/v1/messages")
print(
    f"  carol's tablet queue after the refused send: {len(q['envelopes'])} "
    f"envelopes (all or none)")

print("── 9. MLS: commit ordering with real OpenMLS messages ──")
v = json.load(open(os.path.join(BOOK, "ch27code/server/mls_vectors.json")))
h = lambda k: b64(bytes.fromhex(v[k]))
st, js = alice.call("POST", "/v1/groups/commit", {"message": h("commit_epoch0"),
    "members": [alice.device_id, bob.device_id],
                                                 "joiners": [bob.device_id],
                                                 "welcome": h("welcome")})
show("alice: create group, add bob (commit, epoch 0)", st, js)
st, js = alice.call("POST", "/v1/groups/message",
    {"message": h("application_epoch1")})
show("alice: application message, epoch 1", st, js)
out = {}
def submit(who, key):
    out[who] = who_dev[who].call("POST", "/v1/groups/commit",
        {"message": h(key), "members": [alice.device_id, bob.device_id]})
who_dev = {"alice": alice, "bob": bob}
ts = [threading.Thread(target=submit, args=a) for a in (("alice",
    "commit_epoch1"), ("bob", "bob_commit_epoch1"))]
[t.start() for t in ts]; [t.join() for t in ts]
for w, (st, js) in sorted(out.items()):
    show(f"{w}: concurrent commit for epoch 1", st, js)
st, js = alice.call("POST", "/v1/groups/commit", {"message": h("commit_epoch0"),
    "members": [alice.device_id]})
show("replay of the epoch-0 commit", st, js)
st, js = mallory.call("POST", "/v1/groups/message",
    {"message": h("application_epoch1")})
show("non-member posts to the group", st, js)
names = {bytes.fromhex(x): k for k, x in v.items() if k != "group_id"}
# which OpenMLS messages each device received
for d in (alice, bob):
    st, q = d.call("GET", "/v1/messages")
    print(
        f"  {d.account}'s queue: "
        f"{[names.get(unb64(x['body']), '?') for x in q['envelopes']]}")

print("── 10. Attachments ──")
key, blob = os.urandom(32), io.BytesIO()
attachments.stream_encrypt(io.BytesIO(CANARY * 4000), blob, key)
data = blob.getvalue()
st, a = alice.call("POST", "/v1/attachments", {"size": len(data)})
path = a["upload_url"].split("api.murmur.test")[1]
st, js, _ = edge.request("api", "PUT", path.replace(f"size={len(data)}",
    f"size={len(data)+1}"), data)
show("upload with the size parameter changed", st, js)
st, js, _ = edge.request("api", "PUT", path, data + b"x")
show("upload with a different body length", st, js)
st, js, _ = edge.request("api", "PUT", path, data)
show(f"upload {len(data)} B of STREAM ciphertext", st, js)
st, js, _ = edge.request("api", "PUT", path, data)
show("reuse the signed URL", st, js)
st, js, _ = edge.request("api", "GET", f"/cdn/{a['cdn_id']}")
plain = b"".join(attachments.stream_decrypt(io.BytesIO(js["raw"]), key))
print(
    f"  bob downloads and decrypts: {len(plain)} B, intact: "
    f"{plain == CANARY * 4000}")

srv.terminate(); srv.wait()
print("── 11. What the server and the push providers saw ──")
for line in open(os.path.join(lab, "push-providers.log")).read().splitlines():
    print("  " + line[:230])
log = open(os.path.join(lab, "server.log")).read(); lines = log.splitlines()
print(
    f"  server.log: {len(lines)} lines, e.g.\n    {lines[2]}\n    "
    f"{[l for l in lines if 'sealed' in l][-1]}")
dump = open(os.path.join(lab, "store-dump.bin"), "rb").read()
checks = {
    "plaintext canary in stored bytes (queues, keys, MLS log, blobs)":
        CANARY in dump,
          "canary in server.log": CANARY.decode() in log,
          "access token (eyJ…) in server.log": "eyJ" in log,
          "client IP in server.log": "127.0.0.1" in log,
          "push token in server.log": "apns-token" in log,
          "device ID in server.log": any(d.device_id in log for d in (alice,
          bob, carol))}
for k, found in checks.items():
    print(f"  {k:<64} {'FOUND (!)' if found else 'absent'}")
