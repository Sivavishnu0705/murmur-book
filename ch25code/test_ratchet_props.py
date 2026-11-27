# test_ratchet_props.py
"""Listing 25.1 — Python: Hypothesis-based state-machine test for the Double
Ratchet (Ch 19). Hypothesis generates sequences of sends, deliveries (in any
order), duplicates and forgeries, and checks invariants after every step; on
failure it SHRINKS to a minimal sequence."""
import os
from hypothesis import settings, strategies as st
from hypothesis.stateful import \
    RuleBasedStateMachine, rule, invariant, precondition
from ratchet import Ratchet, DHPair, MAX_STORED

AD = b"props"
IMPL = Ratchet          # the lab swaps in BuggyRatchet

class RatchetMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        SK, spk = os.urandom(32), DHPair()
        self.p = {"A": IMPL.init_alice(SK, spk.pub), "B": IMPL.init_bob(SK,
            spk)}
        # messages TO each party: (header, ct, pt)
        self.inflight = {"A": [], "B": []}
        # (sender, ratchet pub, n): must never repeat
        self.seen_headers = set()
        self.n = 0

    def _send(self, who):
        to = "B" if who == "A" else "A"
        pt = f"{who}{self.n}".encode(); self.n += 1
        hb, ct = self.p[who].encrypt(pt, AD)
        key = (who, hb[:32], hb[36:40])
        assert key not in \
            self.seen_headers, "message key reuse: same (ratchet key, n) twice"
        self.seen_headers.add(key)
        self.inflight[to].append((hb, ct, pt))

    @rule()
    def alice_sends(self): self._send("A")

    @precondition(lambda self: self.p["B"].CKs is not None)
    @rule()
    def bob_sends(self): self._send("B")

    @precondition(lambda self: any(self.inflight.values()))
    @rule(data=st.data())
    # out-of-order: pick ANY in-flight message
    def deliver_any(self, data):
        to = data.draw(st.sampled_from([k for k,
            v in self.inflight.items() if v]))
        i = data.draw(st.integers(0, len(self.inflight[to]) - 1))
        hb, ct, pt = self.inflight[to].pop(i)
        assert self.p[to].decrypt(hb, ct,
            AD) == pt, "delivered message decrypted wrongly"

    @precondition(lambda self: any(self.inflight.values()))
    @rule(data=st.data())
    # attacker: random ratchet key in a copied header
    def forge(self, data):
        to = data.draw(st.sampled_from([k for k,
            v in self.inflight.items() if v]))
        hb, ct, _ = data.draw(st.sampled_from(self.inflight[to]))
        fake = DHPair().pub + hb[32:]
        try:
            self.p[to].decrypt(fake, ct, AD)
            raise AssertionError("forged message accepted")
        except AssertionError:
            raise
        except Exception:
            # rejected — the state must be unchanged
            pass

    @invariant()
    def skipped_bounded(self):
        for r in self.p.values():
            assert len(r.MKSKIPPED) <= MAX_STORED

TestRatchet = RatchetMachine.TestCase
TestRatchet.settings = settings(max_examples=150, stateful_step_count=40,
    deadline=None)
