# redteam.py
"""Listing 31.6 — Python: lab driver — a structured red-team session against
Murmur. Each attack uses tooling from earlier chapters: the intercepting proxy
(Ch 8, Listing 31.5), a "hooked" app with pinning disabled (Ch 25 §25.6), and
the malicious-server mode (Listing 31.4) acting out Chapter 3's compromised
server. Every attack is recorded as a finding: BLOCKED, DETECTED, ACCEPTED, or
VULNERABLE (then fixed and re-run)."""
import \
    json, os, subprocess, sys, tempfile, time, atexit, http.client, socket, ssl
HERE = os.path.dirname(os.path.abspath(__file__))
BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch20code", "ch21code/attach",
    "ch29code/spec", "ch27code/lab", "ch28code/client",
    "ch29code/client", "ch30code/client", "ch30code/core/py",
    "ch31code/redteam"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import x3dh, xeddsa, murmur_pb2 as pb, murmur_groups as mg
from murmur_client import Edge, encode_device_list, b64, unb64
from messenger import Messenger, Edge29, KeyChangeBlocked
from group_service import GroupService
from hardened import HardenedMessenger, ListRollback
from mitm_proxy import InterceptingProxy

root = tempfile.mkdtemp(prefix="murmur31-"); lab = os.path.join(root, "server")
srv = subprocess.Popen([sys.argv[1], "-out", lab], stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, text=True)
atexit.register(srv.kill)
assert srv.stdout.readline().strip() == "ready"
ready = json.load(open(os.path.join(lab, "ready.json")))
edge = Edge29(Edge(lab, ready))
attest = ser.load_pem_private_key(open(os.path.join(lab,
    "lab-attestation-key.pem"), "rb").read(), None)
cert_pub = ser.load_pem_public_key(open(os.path.join(lab,
    "sender-cert-key.pub"), "rb").read())
APPS = {"android": "example.murmur:SHA256:8F:1C:…",
    "ios": "TEAMID1234.example.murmur"}
T0 = time.time(); FINDINGS = []

def evil(path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", ready["evil"])
    c.request("POST" if body is not None else "GET", path,
        json.dumps(body) if body is not None else None)
    r = c.getresponse(); raw = r.read(); return json.loads(raw) if raw else None

def finding(fid, attack, verdict, evidence):
    FINDINGS.append((fid, attack, verdict))
    print(f"  [{verdict}] {fid} {attack}\n      → {evidence}")

def aik_of(m): return Ed25519PrivateKey.from_private_bytes(m.store.identity(
    "account_identity")[1])
def device(cls, account, platform, name, aik=None):
    m = cls(edge, account, platform, APPS[platform], attest, os.path.join(root,
        name), "push-" + name, cert_pub=cert_pub)
    m.login(phr=True); m.create_identity()
    if aik is not None:
        m.store.db.execute("DELETE FROM identity WHERE name='account_identity'")
        m.store.put_identity("account_identity",
            aik.public_key().public_bytes_raw(),
            aik.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw,
            ser.NoEncryption()))
    m.register_keys(T0); return m
def publish(signer, account, devs, version):
    enc = encode_device_list(account, version, [{"id": d.device_id,
        "ik": d.ik.pub, "name": d.platform, "added": 1} for d in devs])
    return signer.call("PUT", "/v1/devicelist", {"encoded": b64(enc),
        "signature": b64(aik_of(signer).sign(enc))})[0]
def first_device(cls, account, platform, name):
    m = device(cls, account, platform, name)
    m.call("PUT", "/v1/aik",
        {"aik": b64(aik_of(m).public_key().public_bytes_raw())})
    return m

print(
    "── setup: alice (Android, Ch 29 client), bob (iPhone + iPad), carol "
    "(phone) ──")
alice = first_device(Messenger, "alice", "android", "alice")
publish(alice, "alice", [alice], 1)
bob = first_device(Messenger, "bob", "ios", "bob-iphone")
ipad = device(Messenger, "bob", "ios", "bob-ipad", aik_of(bob))
publish(bob, "bob", [bob, ipad], 1)
carol = first_device(Messenger, "carol", "android", "carol")
publish(carol, "carol", [carol], 1)
for m in (alice, bob, ipad, carol):
    for a in ("alice", "bob", "carol"): m.refresh_contact(a)
    m.call("PUT", "/v1/delivery-token", {"token": b64(m.token_for_replies)})
ipad.token_for_replies = bob.token_for_replies
bob.call("PUT", "/v1/delivery-token", {"token": b64(bob.token_for_replies)})
alice.send("bob", "hi Bob"); bob.receive(); ipad.receive()
print("  conversation established (alice → bob's iPhone and iPad)")

print("── A. Network attacker: intercepting proxy with a rogue CA ──")
proxy = InterceptingProxy(ready["ports"]["api"], os.path.join(lab, "root.pem"),
    root)
class ProxiedEdge(Edge):
    """The app's network stack pointed at the proxy (a hostile Wi-Fi network).
    """
    def __init__(self, trust_rogue=False, hooked=False):
        super().__init__(lab, dict(ready, ports={"api": proxy.port,
            "auth": ready["ports"]["auth"]}))
        # user-installed CA
        if trust_rogue: self.ctx.load_verify_locations(
            proxy.paths["rogue-root.pem"])
        self.hooked = hooked
    def request(self, host, method, path, body=None, headers=None):
        if not self.hooked:
            return super().request(host, method, path, body, headers)
        # Frida-style hook: the pin check returns early
        pin, self.pin = self.pin, None
        try:
            sock = socket.create_connection(("127.0.0.1", self.ports[host]))
            tls = self.ctx.wrap_socket(sock,
                server_hostname=f"{host}.murmur.test")
            conn = http.client.HTTPConnection(f"{host}.murmur.test")
            conn.sock = tls
            data = json.dumps(body).encode() if isinstance(body, dict) else body
            conn.request(method, path, body=data, headers=headers or {})
            r = conn.getresponse()
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {}), r.headers
        finally: self.pin = pin
def via(e, fn):
    old = alice.edge.inner; alice.edge.inner = e
    try: return fn()
    except Exception as ex: return f"{type(ex).__name__}: {str(ex)[:70]}"
    finally: alice.edge.inner = old
r = via(ProxiedEdge(), lambda: alice.call("GET", "/v1/messages"))
finding("RT-1a", "MITM, device does not trust the rogue CA", "BLOCKED",
    f"handshake refused: {r}")
r = via(ProxiedEdge(trust_rogue=True), lambda: alice.call("GET",
    "/v1/messages"))
finding("RT-1b", "MITM, user-installed rogue CA (chain validates)", "BLOCKED",
    f"SPKI pin check: {r}")
proxy.seen.clear()
r = via(ProxiedEdge(trust_rogue=True, hooked=True), lambda: alice.send("bob",
    "door code is 4711"))
reqs = [s for s in proxy.seen if s[0] == "request"]
send_req = next(
    s for s in reqs if "POST /v1/sealed" in s[1] or "POST /v1/messages" in s[1])
visible = "door code" in send_req[2].decode(errors="replace")
finding("RT-1c",
    "MITM with pinning hooked out of the app: what can the proxy read?",
    "BLOCKED",
    f"{len(reqs)} requests decrypted by the proxy; message text visible in "
    f"the send body: {visible} (E2EE)")
cap = next(s for s in reqs if "Authorization: DPoP" in s[1])
hdrs = dict(l.split(": ", 1) for l in cap[1].split("\r\n")[1:] if ": " in l)
line = cap[1].split("\r\n")[0].split()
st, js, h = edge.request("api", line[0], line[1], cap[2] or None,
    {"Authorization": hdrs["Authorization"], "DPoP": hdrs["DPoP"]})
finding("RT-1d",
    "replay a captured request (token + DPoP proof) from the attacker's "
    "machine", "BLOCKED",
    f"{st} {h.get('WWW-Authenticate', '')[:45]}")
thief_key = Messenger(edge, "x", "android", APPS["android"], attest,
    os.path.join(root, "x"), cert_pub=cert_pub)
thief_key.token = hdrs["Authorization"].split(" ", 1)[1]
from murmur_client import Device
# one plain attempt: no refresh, no retry
st, js = Device.call(thief_key, "GET", "/v1/messages")
finding("RT-1e",
    "use the captured access token with the attacker's own DPoP key", "BLOCKED",
    f"{st} {js.get('www_authenticate', '')[:50]}")
bob.receive(); ipad.receive()

print("── B. Malicious server ──")
# RT-2: forged prekey bundle for a contact we have no session with yet
fake_ik, fake_spk = x3dh.KeyPair(), x3dh.KeyPair()
pq = mlkem.MLKEM1024PrivateKey.generate().public_key().public_bytes_raw()
forged = {"identity_key": b64(fake_ik.pub), "signed_prekey": {"id": 1,
    "pub": b64(fake_spk.pub), "sig": b64(xeddsa.sign(fake_ik.priv,
    b"\x05" + fake_spk.pub))},
    "pq_prekey": {"id": 9, "pub": b64(pq), "sig": b64(xeddsa.sign(fake_ik.priv,
    b"\x08" + pq))}, "pq_last_resort": True}
evil("/evil/bundle", {"Device": carol.device_id, "Bundle": forged})
try: alice.send("carol", "hi Carol"); r = "sent (!)"
except ValueError as e: r = str(e)
finding("RT-2",
    "server substitutes Carol's identity key with a self-consistent forged "
    "bundle", "BLOCKED", r)
# RT-3: an invented device for alice, talking to bob
mal = Messenger(edge, "alice", "android", APPS["android"], attest,
    os.path.join(root, "alice-fake"), cert_pub=cert_pub)
mal.create_identity()
from murmur_client import b64u
import hashlib
jkt = b64u(hashlib.sha256(json.dumps({"crv": "P-256", "kty": "EC",
    "x": mal.jwk["x"], "y": mal.jwk["y"]}, separators=(",",
    ":")).encode()).digest())
dv = evil("/evil/device", {"Account": "alice", "Jkt": jkt,
    "IK": b64(mal.ik.pub)})
mal.device_id, mal.token = dv["device_id"], dv["token"]
for a in ("alice", "bob"): mal.refresh_contact(a)
mal.send("bob", "Bob, it's Alice — new number, please send the code here")
finding("RT-3",
    "server invents a device for Alice (and signs its sender certificate)",
    "BLOCKED",
    f"bob: {[r for r in bob.receive() if r][0]}")
ipad.receive()
# RT-4: device-list rollback after bob's iPad is stolen and revoked
bob.login(phr=True)
bob.call("POST", "/v1/devices/revoke", {"device": ipad.device_id})
publish(bob, "bob", [bob], 2)
# alice saw v2 (iPhone only)
alice.refresh_contact("bob")
evil("/evil/rollback", {"Account": "bob", "Index": 0})
evil("/evil/bypass", {"Account": "bob", "On": True})
# periodic refresh: the server serves v1 again
alice.refresh_contact("bob")
alice.send("bob", "new door code is 9915")
stolen = evil(f"/evil/captured/{ipad.device_id}")["envelopes"]
leaked = [ipad._process(os.urandom(16), unb64(e), None, []) for e in stolen]
finding("RT-4",
    "server rolls Bob's device list back to v1, re-adding the stolen, "
    "revoked iPad", "VULNERABLE",
    f"alice encrypted to the iPad again; the thief's iPad decrypts: "
    f"{[l[3] for l in leaked if l and l[0] == 'message']}")
alice2 = HardenedMessenger(edge, "alice", "android", APPS["android"], attest,
    os.path.join(root, "alice"), cert_pub=cert_pub)
alice2.device_id, alice2.token, alice2.dpop, alice2.jwk, alice2.ik = \
    alice.device_id, alice.token, alice.dpop, alice.jwk, alice.ik
evil("/evil/clear", {"Account": "bob"})
alice2.refresh_contact("bob")   # honest v2 again (version recorded)
evil("/evil/rollback", {"Account": "bob", "Index": 0})
try: alice2.refresh_contact("bob"); r = "accepted (!)"
except ListRollback as e: r = str(e)
finding("RT-4 fix", "same attack against the fixed client (Listing 31.7)",
    "BLOCKED", r)
evil("/evil/clear", {"Account": "bob"})
evil("/evil/bypass", {"Account": "bob", "On": False})
bob.receive()
# RT-5: replay
captured = {}
o = bob.edge.request
def cap_req(*a, **k):
    st, js, h = o(*a, **k)
    if a[1] == "GET" and a[2] == "/v1/messages" and js.get("envelopes"):
        captured["e"] = js["envelopes"][0]["body"]
    return st, js, h
bob.edge.request = cap_req
alice.send("bob", "see you at 6")
bob.receive()
bob.edge.request = o
evil("/evil/replay", {"Device": bob.device_id, "Body": captured["e"]})
finding("RT-5", "server replays a delivered envelope", "BLOCKED",
    f"bob: {bob.receive()}")
# RT-6: push text injection
evil("/evil/push", {"Device": bob.device_id,
    "Text": "Alice: urgent — send 500 EUR to DE89 3704 0044"})
pushed = [l for l in open(os.path.join(lab,
    "push-providers.log")).read().splitlines() if "500 EUR" in l]
# Listing 29.9's logic, modelled
def nse_ch29(push_alert, decrypted):
    # starts from the push's own text
    content = dict(push_alert)
    if decrypted: content.update(title=decrypted[0], body=decrypted[1])
    return content
def nse_fixed(push_alert, decrypted):                        # the fix (§31.2)
    # never display server-supplied text
    content = {"title": "Murmur", "body": "New message"}
    if decrypted: content.update(title=decrypted[0], body=decrypted[1])
    return content
alert = {"title": "Murmur",
    "body": "Alice: urgent — send 500 EUR to DE89 3704 0044"}
finding("RT-6",
    "server/push path injects notification text (no message to decrypt)",
    "VULNERABLE",
    f"provider saw it ({len(pushed)} push); Listing 29.9 shows: "
    f"{nse_ch29(alert, None)['body']!r}")
finding("RT-6 fix", "NSE resets title/body to local constants first", "BLOCKED",
    f"now shows: {nse_fixed(alert, None)['body']!r}")
# RT-7: AIK replacement for carol, who alice never verified
evil_aik = Ed25519PrivateKey.generate(); fake = x3dh.KeyPair()
enc = encode_device_list("carol", 2, [{"id": "dev-evil0000", "ik": fake.pub,
    "name": "phone", "added": 2}])
evil("/evil/devicelist", {"Account": "carol", "List": {"encoded": b64(enc),
    "signature": b64(evil_aik.sign(enc))},
    "AIK": b64(evil_aik.public_key().public_bytes_raw())})
alice.refresh_contact("carol")
own = carol.store.identity("account_identity")[0]
published = unb64(carol.call("GET", "/v1/aik/carol")[1]["aik"])
finding("RT-7",
    "server replaces Carol's AIK and device list (Alice never verified Carol)",
    "DETECTED",
    f"alice: trust = {alice.trust('carol')} (visible notice); carol's own "
    f"monitor: "
    f"published AIK ≠ mine → {'ALARM' if published != own else 'ok'}")
evil("/evil/clear", {"Account": "carol"})
# RT-8: KeyPackage substitution in a group
gs_a, gs_b = GroupService(alice2), GroupService(bob)
gs_b.publish_key_packages(2)
class LyingBinder(mg.CredentialBinder):
    def bind(self, message): return xeddsa.sign(x3dh.KeyPair().priv, message)
from group_service import SqlCipherMlsStore, VerifiedDirectory
fake_core = mg.MurmurGroups.open("bob", bob.device_id,
    SqlCipherMlsStore(Messenger(edge, "bob", "ios", APPS["ios"], attest,
            os.path.join(root, "kp-forger"), cert_pub=cert_pub).db),
            VerifiedDirectory(bob), LyingBinder())
evil("/evil/keypackage", {"Device": bob.device_id,
    "KP": b64(fake_core.key_packages(1, False)[0])})
alice2.refresh_contact("bob")
try: gs_a.create(["alice"], ["bob"]); r = "group created (!)"
except mg.GroupError as e: r = getattr(e, "msg", str(e))
finding("RT-8",
    "server substitutes a KeyPackage for Bob's iPhone (credential claims "
    "bob/iPhone)", "BLOCKED", r)
finding("RT-9", "server drops a message (accepts it, never queues it)",
    "ACCEPTED",
    "G-10 excludes guaranteed delivery (Ch 3); later messages decrypt via "
    "skipped keys; gap not shown to users (open: §31.1)")

actions = evil("/evil/log")
srv.terminate(); srv.wait()
print("── summary ──")
print(f"  malicious-server actions taken: {len(actions)}")
from collections import Counter
print("  " + "  ".join(f"{k}: {v}" for k, v in sorted(Counter(v for _, _,
    v in FINDINGS).items())))
