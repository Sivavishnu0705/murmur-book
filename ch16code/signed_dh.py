# signed_dh.py
"""Listing 16.1 — Python: raw DH and its MITM; naive signed-DH and the identity-misbinding
attack; the SIGMA fix (sign the ephemerals, MAC your own identity under a key from the DH)."""
from ake import *

# Registered identities: name -> Ed25519 public key (think: Murmur's key directory, Ch 20)
alice_sk, alice_pk = sig_keypair()
bob_sk, bob_pk = sig_keypair()
eve_sk, eve_pk = sig_keypair()            # Eve is a legitimate, registered user
directory = {b"alice": alice_pk, b"bob": bob_pk, b"eve": eve_pk}

print("── Fig 16.1: raw DH, active MITM ──")
a, A = dh_keypair(); b, B = dh_keypair()
m1, M1 = dh_keypair(); m2, M2 = dh_keypair()      # Mallory answers each side with her own value
k_alice = dh(a, M1)        # Alice thinks she talks to Bob
k_bob = dh(b, M2)          # Bob thinks he talks to Alice
print(f"  Alice's key {fp(k_alice)}  == Mallory's {fp(dh(m1, A))}: {k_alice == dh(m1, A)}")
print(f"  Bob's key   {fp(k_bob)}  == Mallory's {fp(dh(m2, B))}: {k_bob == dh(m2, B)}")
print("  → Mallory decrypts, reads and re-encrypts everything; neither side can tell.")

# ---------------------------------------------------------------------------------------------
# ⚠️ INSECURE — naive signed DH: each party signs the two ephemerals, but not identities.
#   1  I → R : g^x
#   2  R → I : g^y, R, Sig_R(g^x, g^y)
#   3  I → R : I, Sig_I(g^y, g^x)
# ---------------------------------------------------------------------------------------------
def naive_signed_dh(attacker_swaps_identity):
    x, gx = dh_keypair()                                   # initiator = Alice
    y, gy = dh_keypair()                                   # responder = Bob
    sig_r = bob_sk.sign(gx + gy)                           # message 2
    assert verify(directory[b"bob"], sig_r, gx + gy)       # Alice: "I am talking to bob" ✓
    msg3 = (b"alice", alice_sk.sign(gy + gx))              # message 3
    if attacker_swaps_identity:
        # Eve strips Alice's identity and signature and substitutes her OWN: she can sign
        # (g^y, g^x) because both values travelled in the clear.
        msg3 = (b"eve", eve_sk.sign(gy + gx))
    name, sig_i = msg3
    bob_accepts = verify(directory[name], sig_i, gy + gx)
    k_a, k_b = dh(x, gy), dh(y, gx)
    return name, bob_accepts, k_a == k_b

print("── Fig 16.2: naive signed DH — identity misbinding ──")
name, ok, same = naive_signed_dh(False)
print(f"  honest run:   Bob accepts peer={name.decode()!r:7} ok={ok}  Alice&Bob share key={same}")
name, ok, same = naive_signed_dh(True)
print(f"  Eve swaps ID: Bob accepts peer={name.decode()!r:7} ok={ok}  Alice&Bob share key={same}")
print("  → Bob believes he shares a key with EVE; he actually shares it with ALICE.")
print("    Alice's messages ('I'll pay the invoice') are credited to Eve. Eve never knew the key —")
print("    that's the point: authentication bound the WRONG identity to a correct key.")

# ---------------------------------------------------------------------------------------------
# SIGMA (basic form): sign the ephemerals, and MAC your own identity with a key derived from DH.
#   1  I → R : g^x
#   2  R → I : g^y, R, Sig_R(g^x, g^y), MAC_Km(R)
#   3  I → R : I,       Sig_I(g^y, g^x), MAC_Km(I)
#   K_m (MAC key) and K_s (session key) both come from g^xy; only the two real parties know them.
# ---------------------------------------------------------------------------------------------
def sigma(attacker_swaps_identity):
    x, gx = dh_keypair(); y, gy = dh_keypair()
    km_r = kdf(dh(y, gx), b"sigma mac", salt=h(gx, gy))
    msg2 = (gy, b"bob", bob_sk.sign(b"R" + gx + gy), mac(km_r, b"R" + b"bob"))
    # Alice
    km_i = kdf(dh(x, msg2[0]), b"sigma mac", salt=h(gx, msg2[0]))
    assert verify(directory[msg2[1]], msg2[2], b"R" + gx + gy) and mac_ok(km_i, b"R" + msg2[1], msg2[3])
    msg3 = (b"alice", alice_sk.sign(b"I" + gy + gx), mac(km_i, b"I" + b"alice"))
    if attacker_swaps_identity:
        # Eve can still produce a valid SIGNATURE on (g^y, g^x)… but not the MAC over "eve",
        # because K_m is derived from g^xy, which she does not know. Best she can do: guess.
        msg3 = (b"eve", eve_sk.sign(b"I" + gy + gx), os.urandom(32))
    name, sig_i, tag = msg3
    sig_ok = verify(directory[name], sig_i, b"I" + gy + gx)
    mac_ok_ = mac_ok(km_r, b"I" + name, tag)
    return name, sig_ok, mac_ok_

print("── Fig 16.3: SIGMA ──")
for swap in (False, True):
    name, s_ok, m_ok = sigma(swap)
    verdict = "ACCEPT" if s_ok and m_ok else "REJECT"
    print(f"  {'Eve swaps ID' if swap else 'honest run  '}: peer={name.decode()!r:7} signature ok={s_ok!s:5} "
          f"MAC ok={m_ok!s:5} → {verdict}")
print("  → the MAC proves 'the party who knows g^xy calls itself <name>': identity is bound to the key.")
