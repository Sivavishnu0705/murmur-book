# fuzz.py
"""Listing 19.2 — Python test: randomized out-of-order delivery fuzz test. Two
parties send in random bursts; the network drops, duplicates and reorders.
Invariants: every delivered original decrypts to the right plaintext exactly
once; duplicates and forgeries are rejected; state is never corrupted by a
rejected message."""
import random
from ratchet import Ratchet, DHPair

AD = b"fuzz-ad"

def trial(seed, n_msgs=120, p_drop=0.1, p_dup=0.1, window=8):
    rnd = random.Random(seed)
    SK, spk = bytes(rnd.randrange(256) for _ in range(32)), DHPair()
    parties = {"A": Ratchet.init_alice(SK, spk.pub), "B": Ratchet.init_bob(SK,
        spk)}
    # in-flight messages TO each party
    queues = {"A": [], "B": []}
    ok = dup_rej = forged_rej = dropped = 0
    sent = 0
    while sent < n_msgs or any(queues.values()):
        if sent < n_msgs and (rnd.random() < 0.6 or not any(queues.values())):
            # Bob can send only after receiving Alice's first message (he has no
            # sending chain yet)
            who = "B" if (
                parties["B"].CKs is not None and rnd.random() < 0.5) else "A"
            to = "B" if who == "A" else "A"
            pt = f"{who}-{sent}".encode()
            hb, ct = parties[who].encrypt(pt, AD); sent += 1
            if rnd.random() < p_drop:
                dropped += 1; continue
            copies = 2 if rnd.random() < p_dup else 1
            for _ in range(copies):
                queues[to].insert(max(0,
                    len(queues[to]) - rnd.randrange(window)), (hb, ct, pt))
        else:
            to = rnd.choice([k for k, q in queues.items() if q])
            hb, ct, pt = queues[to].pop(rnd.randrange(min(window,
                len(queues[to]))))
            # occasionally deliver a forged copy first
            if rnd.random() < 0.05:
                try:
                    parties[to].decrypt(hb, ct[:-1] + bytes([ct[-1] ^ 1]), AD)
                    raise AssertionError("forgery accepted")
                except AssertionError: raise
                except Exception: forged_rej += 1
            try:
                got = parties[to].decrypt(hb, ct, AD)
                assert got == pt, "wrong plaintext"
                ok += 1
            except Exception as e:
                if isinstance(e, AssertionError): raise
                # a duplicate whose key was already used/deleted
                dup_rej += 1
    return ok, dup_rej, forged_rej, dropped, sent

if __name__ == "__main__":
    tot = [0] * 5
    for seed in range(200):
        r = trial(seed)
        assert r[0] + r[3] == r[4], (
            f"seed {seed}: delivered {r[0]} + dropped {r[3]} != sent {r[4]}")
        tot = [a + b for a, b in zip(tot, r)]
    print(
        f"  200 random trials: {tot[4]} messages sent, {tot[3]} dropped, "
        f"{tot[0]} decrypted exactly once,")
    print(
        f"  {tot[1]} duplicate deliveries rejected, {tot[2]} forged "
        f"deliveries rejected, 0 invariant violations")
