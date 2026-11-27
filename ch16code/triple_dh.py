# triple_dh.py
"""Listing 16.2 — Python: triple-DH key derivation (the core of X3DH, Ch 18),
its implicit authentication, deniability, and KCI resistance compared with a
static-static design."""
from ake import *

def triple_dh_initiator(ia, ea, IB, EB):
    # DH1 = DH(IA, EB) authenticates Alice (needs ia) DH2 = DH(EA, IB)
    # authenticates Bob (needs ib) DH3 = DH(EA, EB) forward secrecy (ephemerals
    # deleted after use)
    return dh(ia, EB), dh(ea, IB), dh(ea, EB)

def triple_dh_responder(ib, eb, IA, EA):
    return dh(eb, IA), dh(ib, EA), dh(eb, EA)

def derive(dh1, dh2, dh3, IA, IB, EA, EB):
    # Transcript binding: who is initiator/responder and which values were used
    # go into the KDF.
    return kdf(dh1 + dh2 + dh3, b"toy-3dh v1", salt=h(b"I", IA, b"R", IB, EA,
        EB))

ia, IA = dh_keypair(); ib, IB = dh_keypair()      # long-term identity keys
ea, EA = dh_keypair(); eb, EB = dh_keypair()      # fresh ephemerals

print("── Fig 16.4: triple DH ──")
k_alice = derive(*triple_dh_initiator(ia, ea, IB, EB), IA, IB, EA, EB)
k_bob = derive(*triple_dh_responder(ib, eb, IA, EA), IA, IB, EA, EB)
print(f"  Alice: {fp(k_alice)}   Bob: {fp(k_bob)}   agree={k_alice == k_bob}")
print(
    "  No signatures were sent: each side is authenticated IMPLICITLY — only "
    "the holder of the")
print(
    "  matching identity private key can compute the same key, so a wrong "
    "peer simply can't talk.")

print("── Implicit authentication: Mallory impersonates Alice without ia ──")
mi, MI = dh_keypair(); me, ME = dh_keypair()
# claims identity IA
k_mallory = derive(dh(mi, EB), dh(me, IB), dh(me, EB), IA, IB, ME, EB)
k_bob2 = derive(*triple_dh_responder(ib, eb, IA, ME), IA, IB, ME, EB)
print(
    f"  Mallory's key == Bob's key: {k_mallory == k_bob2}  → first message "
    f"fails to decrypt")

print("── Deniability: Bob can produce the same transcript and key ALONE ──")
# Bob invents 'Alice's' ephemeral himself
fake_ea, FAKE_EA = dh_keypair()
forged = derive(dh(eb, IA), dh(ib, FAKE_EA), dh(eb, FAKE_EA), IA, IB, FAKE_EA,
    EB)
real_alice_would_get = derive(dh(ia, EB), dh(fake_ea, IB), dh(fake_ea, EB), IA,
    IB, FAKE_EA, EB)
print(
    f"  Bob's forged session key == what Alice would compute: "
    f"{forged == real_alice_would_get}")
print(
    "  → a transcript proves nothing to a third party: Bob could have made "
    "it. (A signature would.)")

print(
    "── KCI: Bob's identity key ib leaks. Can Mallory now impersonate ALICE "
    "to Bob? ──")
# Toy 'static-static + ephemeral' design:  K = KDF( DH(IA, IB) ‖ DH(EA, EB) )
def ss_responder(ib, eb, IA, EA):
    return kdf(dh(ib, IA) + dh(eb, EA), b"toy-ss", salt=h(IA, IB, EA, EB))
me, ME = dh_keypair()
k_bob_ss = ss_responder(ib, eb, IA, ME)
# uses the LEAKED ib
k_mal_ss = kdf(dh(ib, IA) + dh(me, EB), b"toy-ss", salt=h(IA, IB, ME, EB))
print(
    f"  static-static design: Mallory (knows ib, not ia) matches Bob's key: "
    f"{k_bob_ss == k_mal_ss}  ← KCI")
k_bob_3 = derive(*triple_dh_responder(ib, eb, IA, ME), IA, IB, ME, EB)
# Mallory has ib and her own me; she lacks ia and eb, so DH(IA, EB) is out of
# reach. The best she can do is substitute a value she CAN compute (here DH(me,
# EB)); any such value is wrong.
k_mal_3 = derive(dh(me, EB), dh(ib, ME), dh(me, EB), IA, IB, ME, EB)
print(
    f"  triple DH:            Mallory (knows ib, not ia)  matches Bob's key: "
    f"{k_bob_3 == k_mal_3}")
print(
    "  → DH(IA, EB) needs ia or eb; a leaked ib doesn't help impersonate "
    "OTHERS to Bob")
print(
    "    (as long as Bob's EB is fresh — X3DH's signed prekeys revisit this "
    "in Ch 18).")
