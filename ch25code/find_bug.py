# find_bug.py
"""Listing 25.7 — Python: lab — find the planted ratchet flaw two automated ways (the third,
the review, is in the text): (1) the property-based state machine of Listing 25.1, (2) a
mutation fuzzer whose oracle is 'after any rejected input, the session still works'."""
import contextlib, io, os, random
from hypothesis import settings
from hypothesis.stateful import run_state_machine_as_test
import test_ratchet_props as props
from ratchet import Ratchet, DHPair
from buggy_ratchet import BuggyRatchet

AD = b"props"

def property_test(impl):
    props.IMPL = impl
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            run_state_machine_as_test(props.RatchetMachine,
                settings=settings(max_examples=300, stateful_step_count=40, deadline=None, print_blob=False))
        return "passed (300 random runs)"
    except Exception as e:
        notes = getattr(e, "__notes__", []) or out.getvalue().splitlines()
        steps = [n for n in notes if n.startswith("state.") and "skipped_bounded" not in n and "teardown" not in n]
        return (f"FAILED — {type(e).__name__} in a later step\n      minimal failing sequence (shrunk by Hypothesis):\n        "
                + "\n        ".join(steps))

def fuzz(impl, budget=20000, seed=25):
    rnd = random.Random(seed)
    broken, first = 0, None
    for it in range(1, budget + 1):
        SK, spk = os.urandom(32), DHPair()
        a, b = impl.init_alice(SK, spk.pub), impl.init_bob(SK, spk)
        h1, c1 = a.encrypt(b"first", AD); b.decrypt(h1, c1, AD)
        h2, c2 = a.encrypt(b"second", AD)                  # legitimate, delivered after the junk
        junk = bytearray(h2 + c2)
        for _ in range(rnd.randint(1, 3)):                 # flip 1–3 random bits anywhere
            junk[rnd.randrange(len(junk))] ^= 1 << rnd.randrange(8)
        if bytes(junk) == h2 + c2:
            continue                                       # flips cancelled out: not a mutation
        try:
            b.decrypt(bytes(junk[:40]), bytes(junk[40:]), AD)
        except Exception:
            pass                                           # rejection is fine…
        try:
            assert b.decrypt(h2, c2, AD) == b"second"      # …but the session must still work
        except Exception:
            broken += 1
            if first is None:
                pos = next(i for i in range(len(junk)) if junk[i] != (h2 + c2)[i])
                first = (it, pos, "header ratchet key" if pos < 32 else "header counters" if pos < 40 else "ciphertext")
    if not broken:
        return f"passed ({budget} mutated inputs)"
    it, pos, region = first
    return (f"FAILED: {broken} of {budget} rejected inputs broke the session; first at input {it} "
            f"(changed byte {pos}: {region})")

if __name__ == "__main__":
    for name, impl in (("correct Ratchet", Ratchet), ("BuggyRatchet", BuggyRatchet)):
        print(f"── {name} ──")
        print(f"  property test: {property_test(impl)}")
        print(f"  mutation fuzz: {fuzz(impl)}")
