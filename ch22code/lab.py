# lab.py
"""Listing 22.4 — Python: lab — remove a member properly in a 10-member group; cost comparison;
in-group impersonation; weak post-compromise security."""
import copy
from senderkeys import SenderChain, ReceiverState

names = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "mallory"]
G = "book-club"
pairwise_msgs = 0
def pairwise_send(to, payload):           # stands in for a Double Ratchet message (Ch 19)
    global pairwise_msgs; pairwise_msgs += 1; members[to]["recv"].install(payload)

members = {n: {"send": SenderChain(G, n), "recv": ReceiverState()} for n in names}
for n in names:                          # everyone distributes their sender key to everyone else
    for m in names:
        if m != n: pairwise_send(m, members[n]["send"].distribution())
print(f"── Setup: {len(names)} members, sender-key distribution = {pairwise_msgs} pairwise messages ──")

def broadcast(sender, text):
    return members[sender]["send"].encrypt(text.encode())

def who_can_read(msg, readers):
    ok = []
    for r in readers:
        try: members[r]["recv"].decrypt(copy.deepcopy(msg)); ok.append(r)
        except Exception: pass
    return ok

print("── Fig 22.1: cost of one 1 KB message, 10 members × 3 devices each ──")
n, d, size = 10, 3, 1024
print(f"  pairwise fan-out: {(n * d - 1)} ciphertexts, ~{(n * d - 1) * size // 1024} KB uploaded by the sender")
print(f"  sender keys:      1 ciphertext, ~1 KB uploaded; the server copies it to {(n * d - 1)} devices")

print("── Remove mallory WITHOUT rotation ──")
mallory_copy = members["mallory"]["recv"]           # she keeps everything she had
del members["mallory"]
m1 = broadcast("alice", "new meeting place: the library")
print(f"  mallory decrypts alice's new message: {mallory_copy.decrypt(copy.deepcopy(m1))!r}  ← still reads")

print("── Remove mallory WITH rotation (every remaining member rotates and redistributes) ──")
remaining = [x for x in names if x != "mallory"]
before = pairwise_msgs
for s in remaining:
    members[s]["send"] = SenderChain(G, s)          # fresh chain id, chain key and signing key
    for r in remaining:
        if r != s: pairwise_send(r, members[s]["send"].distribution())
print(f"  rotation cost: {pairwise_msgs - before} pairwise messages ({len(remaining)} senders × {len(remaining) - 1} recipients)")
m2 = broadcast("alice", "new place, for real: the café")
try:
    mallory_copy.decrypt(copy.deepcopy(m2)); print("  mallory reads it (!)")
except KeyError as e:
    print(f"  mallory: {e}")
print(f"  remaining members who can read it: {len(who_can_read(m2, remaining))} of {len(remaining) - 1} (everyone except the sender)")

print("── Impersonation inside the group ──")
# carol knows alice's chain key (everyone does) — she can produce a valid CIPHERTEXT "from alice":
from senderkeys import step, kn, AESGCM
c = members["carol"]["recv"].chains[(G, "alice")]
ck, mk = step(c["ck"]); key, nonce = kn(mk)
hdr = G.encode() + b"|alice|" + c["chain_id"] + c["it"].to_bytes(4, "big")
forged = {"hdr": hdr, "group": G, "sender": "alice", "chain_id": c["chain_id"], "it": c["it"],
          "ct": AESGCM(key).encrypt(nonce, b"cancel the meeting", hdr), "sig": b"\0" * 64}
lax = ReceiverState(verify_signatures=False); lax.install({**members["alice"]["send"].distribution(), "iteration": c["it"], "ck": c["ck"]})
print(f"  without signature checks, bob accepts carol's forgery as alice: {lax.decrypt(copy.deepcopy(forged))!r}")
try:
    members["bob"]["recv"].decrypt(copy.deepcopy(forged)); print("  accepted (!)")
except ValueError as e:
    print(f"  with signature checks: {e}")

print("── Weak PCS: an attacker copies bob's receiver state once ──")
stolen = copy.deepcopy(members["bob"]["recv"])
read = sum(1 for i in range(50) if stolen.decrypt(copy.deepcopy(broadcast("alice", f"msg {i}"))))
print(f"  50 later messages from alice, attacker reads {read}: no healing until alice rotates her sender key")
members["alice"]["send"] = SenderChain(G, "alice")
for r in remaining:
    if r != "alice": pairwise_send(r, members["alice"]["send"].distribution())
try:
    stolen.decrypt(broadcast("alice", "after rotation")); print("  still reads (!)")
except KeyError:
    print("  after alice rotates (distributed pairwise, which the attacker can't read): locked out")

print("── Bounded skipped-key storage ──")
from senderkeys import MAX_SKIPPED
z = SenderChain(G, "zoe"); rz = ReceiverState(); rz.install(z.distribution())
msgs = [z.encrypt(b"x") for _ in range(4000)]
rz.decrypt(msgs[1999]); rz.decrypt(msgs[3999])          # two gaps of ~2,000 messages each
print(f"  stored skipped keys: {len(rz.chains[(G, 'zoe')]['skipped'])} (cap {MAX_SKIPPED})")
try:
    rz.decrypt(msgs[0]); print("  oldest still decryptable")
except ValueError:
    print("  the oldest skipped message's key was evicted: undecryptable, as intended")
print(f"  a recent skipped message still decrypts: {rz.decrypt(msgs[3998]) == b'x'}")
