# toys.py
"""Listing 16.3 — Python: five toy AKEs for the lab, each with a deliberate flaw
(⚠️ INSECURE), and the attack and fix for each (Listing 16.4 prints the
results). Read each protocol's comment block first and try to find the flaw
before reading its attack."""
from ake import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ═════════ Toy 1: shared-key challenge–response (mutual authentication)
# ═════════════════════ 1 I → R : N_I 2 R → I : N_R, MAC_K(N_I) 3 I → R :
# MAC_K(N_R) Both devices share K and either can start a session.
class Toy1Party:
    def __init__(self, k, name, fixed):
        self.k, self.name, self.fixed = k, name, fixed
    def tag(self, challenge, responder, initiator, nonces):
        if self.fixed:   # FIX: role label + identities + both nonces
            return mac(self.k,
                b"toy1 response|" + responder + b"|" + initiator + b"|" +
                nonces)
        # ⚠️ the response says nothing about WHO answers
        return mac(self.k, challenge)
    def respond(self, n_i, initiator):                   # acting as responder
        n_r = os.urandom(16)
        return n_r, self.tag(n_i, self.name, initiator, n_i + n_r)

def toy1(fixed):
    k = os.urandom(32)
    alice = Toy1Party(k, b"alice", fixed)
    # Mallory, who does NOT know K, wants Alice to accept her as "bob".
    # session 1: Alice → "bob": N_A
    n_a = os.urandom(16)
    # Session 2: Mallory starts a NEW session with Alice, claiming to be bob,
    # and reflects N_A.
    # Alice computes the tag for her own challenge
    _, alice_answer = alice.respond(n_a, b"bob")
    # session 1, message 2 from "bob"
    n_m = os.urandom(16)
    expected = alice.tag(n_a, b"bob", b"alice", n_a + n_m)
    # does Alice accept "bob"?
    return hmac.compare_digest(alice_answer, expected)

# ═════════ Toy 2: signed DH without identities (Listing 16.1, compact)
# ══════════════════════ 1 I → R : g^x 2 R → I : g^y, R, Sig_R(g^x,g^y) 3 I → R
# : I, Sig_I(g^y,g^x)
def toy2(fixed):
    a_sk, a_pk = sig_keypair()
    b_sk, b_pk = sig_keypair()
    e_sk, e_pk = sig_keypair()
    d = {b"alice": a_pk, b"bob": b_pk, b"eve": e_pk}
    x, gx = dh_keypair(); y, gy = dh_keypair()
    km = kdf(dh(y, gx), b"toy2 mac", salt=h(gx, gy))
    # Eve replaces message 3 with her identity and her signature over the public
    # ephemerals.
    name, sig = b"eve", e_sk.sign(gy + gx)
    # (fixed version: Eve can't compute MAC_Km("eve"))
    tag = os.urandom(32)
    ok = verify(d[name], sig, gy + gx)
    # FIX: SIGMA — MAC own identity under K_m
    if fixed:
        ok = ok and mac_ok(km, b"I" + name, tag)
    # does Bob accept "eve" as his peer?
    return ok

# ═════════ Toy 3: one-pass authenticated key agreement to a server
# ═════════════════ 1  C → S : C, g^x, Sig_C(g^x)            K = DH(x, S_static)
#   2  C → S : AEAD_K(seq, "pay 100 to Mallory")   …
class Toy3Server:
    def __init__(self, fixed):
        self.s, self.S = dh_keypair(); self.fixed = fixed; self.executed = []
    # FIX: a fresh server ephemeral per session
    def hello(self):
        self.y, self.gy = dh_keypair()
        return self.gy
    def session(self, client_pk, gx, sig, records, gy=None):
        transcript = gx + (gy or b"")
        if not verify(client_pk, sig, transcript):
            return "reject"
        k = kdf(dh(self.s, gx) + (dh(self.y, gx) if self.fixed else b""),
            b"toy3", salt=h(transcript))
        for nonce, ct in records:
            try:
                self.executed.append(AESGCM(k).decrypt(nonce, ct,
                    None).decode())
            except Exception:
                return "reject (records don't decrypt)"
        return "accepted"

def toy3(fixed):
    srv = Toy3Server(fixed)
    c_sk, c_pk = sig_keypair()
    def client_run():
        gy = srv.hello() if fixed else None
        x, gx = dh_keypair()
        k = kdf(dh(x, srv.S) + (dh(x, gy) if fixed else b""), b"toy3",
            salt=h(gx + (gy or b"")))
        nonce = os.urandom(12)
        recs = [(nonce, AESGCM(k).encrypt(nonce, b"pay 100 to Mallory", None))]
        return gx, c_sk.sign(gx + (gy or b"")), recs, gy
    gx, sig, recs, gy = client_run()
    # the real session; Mallory records it
    srv.session(c_pk, gx, sig, recs, gy)
    if fixed:
        # a new session gets a NEW server ephemeral
        srv.hello()
    # Mallory replays it
    result = srv.session(c_pk, gx, sig, recs, srv.gy if fixed else None)
    return result, len(srv.executed)

# ═════════ Toy 4: static-static + ephemeral-ephemeral
# ═══════════════════════════════════════ K = KDF( DH(I_A, I_B) ‖ DH(E_A, E_B) )
# — Bob's identity key i_b has leaked.
def toy4(fixed):
    ia, IA = dh_keypair(); ib, IB = dh_keypair(); eb, EB = dh_keypair()
    # Mallory's ephemeral, claiming to be Alice
    me, ME = dh_keypair()
    if not fixed:
        k_bob = kdf(dh(ib, IA) + dh(eb, ME), b"toy4")
        # DH(IA, IB) computed from the leaked ib
        k_mal = kdf(dh(ib, IA) + dh(me, EB), b"toy4")
    # FIX: triple DH (Listing 16.2)
    else:
        k_bob = kdf(dh(eb, IA) + dh(ib, ME) + dh(eb, ME), b"toy4")
        # DH(IA, EB) unreachable
        k_mal = kdf(dh(me, EB) + dh(ib, ME) + dh(me, EB), b"toy4")
    # can Mallory impersonate Alice to Bob?
    return k_bob == k_mal

# ═════════ Toy 5: negotiated suites, "Finished" under the negotiated key
# ═══════════ 1  C → S : offer = [strong, weak], g^x      2  S → C : choice, g^y
# 3 both : k = KDF(g^xy) truncated to the suite's strength ("weak" = 16 bits, an
# export suite) 4  both  : Finished = MAC_k(choice)
STRENGTH = {"strong": 32, "weak": 2}

def toy5(fixed):
    x, gx = dh_keypair(); y, gy = dh_keypair(); secret = dh(x, gy)
    offer_sent = ["strong", "weak"]
    # Mallory strips "strong" in transit
    offer_seen = ["weak"]
    choice = offer_seen[0]
    def suite_key(c):
        return kdf(secret, b"toy5 " + c.encode())[:STRENGTH[c]].ljust(32, b"\0")
    if not fixed:
        # Mallory brute-forces the 16-bit key from the server's Finished, then
        # forges the client's view. 65,536 HMACs take a fraction of a second.
        srv_fin = mac(suite_key(choice), choice.encode())
        for guess in range(1 << 16):
            kg = guess.to_bytes(2, "big").ljust(32, b"\0")
            if mac(kg, choice.encode()) == srv_fin:
                break
        client_ok = mac_ok(suite_key(choice), choice.encode(), mac(kg,
            choice.encode()))
        return client_ok, guess
    # FIX: Finished key from the FULL secret, MAC over the WHOLE transcript as
    # each side saw it
    fin_key = kdf(secret, b"toy5 finished")
    srv_fin = mac(fin_key, h(*(o.encode() for o in offer_seen), gx,
        choice.encode(), gy))
    client_ok = mac_ok(fin_key, h(*(o.encode() for o in offer_sent), gx,
        choice.encode(), gy), srv_fin)
    return client_ok, None
