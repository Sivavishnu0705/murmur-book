# lab.py
"""Listing 19.5 — Python: lab — "Ratchet under stress": a lossy, reordering
network; state theft at message 50 and healing; skip-key DoS; replay; and the
danger of restoring old state."""
import copy, random, time
from ratchet import Ratchet, DHPair, Header, MAX_SKIP

AD = b"\x05" + b"A" * 32 + b"\x05" + b"B" * 32
rnd = random.Random(19)
SK, spk = bytes(32), DHPair()
alice, bob = Ratchet.init_alice(SK, spk.pub), Ratchet.init_bob(SK, spk)

print("── 1. State theft at message 50, then healing ──")
# A conversation in turns: Alice sends 3, Bob replies 2, ... Mallory records ALL
# ciphertexts.
mallory = None
log = []
turn = 0
msg_no = 0
while msg_no < 90:
    sender, receiver, burst = (alice, bob, 3) if turn % 2 == 0 else (bob, alice,
        2)
    for _ in range(burst):
        msg_no += 1
        who = 'Alice' if sender is alice else 'Bob'
        pt = f"msg {msg_no} from {who}".encode()
        hb, ct = sender.encrypt(pt, AD)
        receiver.decrypt(hb, ct, AD)
        if msg_no == 50:
            # malware copies Bob's ENTIRE state
            mallory = copy.deepcopy(bob)
            stolen_at = msg_no
        if mallory is not None and msg_no > stolen_at:
            # Mallory tries to read Alice's messages with her copy of Bob's
            # state. Bob's new sends are out of reach from msg 54: they use a
            # ratchet key she never saw. She never sends anything.
            if sender is alice:
                try:
                    mallory.decrypt(hb, ct, AD)
                    log.append((msg_no, "Alice→Bob", "READ"))
                except Exception:
                    log.append((msg_no, "Alice→Bob", "—"))
            else:
                log.append((msg_no, "Bob→Alice", "(new Bob ratchet key)"))
    turn += 1
for n, d, r in log[:12]:
    print(f"  msg {n:2} {d:10} Mallory: {r}")
first_fail = next(n for n, d, r in log if r == "—")
print(
    f"  → Mallory reads Alice's messages until Bob's reply carries a fresh "
    f"ratchet key and Alice")
print(
    f"    answers with one of her own; from msg {first_fail} on she reads "
    f"nothing (healed after one round trip).")

print("── 2. Lossy network: 20% drop, 10% duplicate, reordering within 10 ──")
alice, bob = Ratchet.init_alice(SK, spk.pub), Ratchet.init_bob(SK, spk)
inflight, sent, delivered, rejected, lost = [], 0, 0, 0, 0
for i in range(500):
    hb, ct = alice.encrypt(f"m{i}".encode(), AD); sent += 1
    if rnd.random() < 0.2: lost += 1; continue
    inflight.insert(max(0, len(inflight) - rnd.randrange(10)), (hb, ct))
    if rnd.random() < 0.1:
        inflight.insert(max(0, len(inflight) - rnd.randrange(10)), (hb, ct))
    while len(inflight) > 10 or (inflight and rnd.random() < 0.5):
        h, c = inflight.pop(0)
        try: bob.decrypt(h, c, AD); delivered += 1
        except Exception: rejected += 1
for h, c in inflight:
    try: bob.decrypt(h, c, AD); delivered += 1
    except Exception: rejected += 1
print(
    f"  sent {sent}, lost {lost}, decrypted {delivered} (= sent − lost: "
    f"{delivered == sent - lost}), "
    f"duplicates rejected {rejected}, skipped keys still stored "
    f"{len(bob.MKSKIPPED)} (the lost ones)")

print("── 3. Skip-key DoS: a header claiming n = 10,000,000 ──")
hb, ct = alice.encrypt(b"x", AD)
evil = Header.decode(hb); evil.n = 10_000_000
t = time.perf_counter()
try:
    bob.decrypt(evil.encode(), ct, AD)
except ValueError as e:
    print(
        f"  rejected in {(time.perf_counter() - t) * 1000:.2f} ms: {e}; "
        f"Bob's state unchanged: "
        f"Nr={bob.Nr}")
print(
    f"  (without MAX_SKIP Bob would derive and store 10 million keys before "
    f"the AEAD check fails)")

print("── 4. Restoring Bob's state from an old backup ──")
alice, bob = Ratchet.init_alice(SK, spk.pub), Ratchet.init_bob(SK, spk)
hb, ct = alice.encrypt(b"hi", AD); bob.decrypt(hb, ct, AD)
# e.g. an iCloud/Google backup at this moment
backup = copy.deepcopy(bob)
p1 = b"Meet at the north gate at 9."
# Bob sends after the backup
h1, c1 = bob.encrypt(p1, AD)
# phone restored from backup
bob = backup
p2 = b"The password is tangerine-42"
# same chain position → same key, same nonce
h2, c2 = bob.encrypt(p2, AD)
print(f"  same header (ratchet key, n) reused: {h1 == h2}")
x = bytes(a ^ b for a, b in zip(c1, c2))
# attacker who knows/guesses p1
recovered = bytes(a ^ b for a, b in zip(x, p1))
print(f"  ciphertext1 ⊕ ciphertext2 ⊕ known p1 → {recovered!r}")
print(
    "  → AES-GCM nonce reuse: plaintext recovered (and GCM's authentication "
    "key exposed). Never restore ratchet state.")
