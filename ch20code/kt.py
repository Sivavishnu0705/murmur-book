# kt.py
"""Listing 20.4 — Python: a minimal key-transparency log (concept only). Entries
bind an account to its AIK and device-list hash; the server publishes signed
tree heads (STH); clients verify inclusion proofs; owners monitor their own
entries; clients gossip STHs to detect a server that shows different users
different logs (split view). Hashing follows RFC 9162 (Certificate Transparency
v2): leaf = H(0x00 ‖ d), node = H(0x01 ‖ l ‖ r)."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

H = lambda b: hashlib.sha256(b).digest()
leaf = lambda d: H(b"\x00" + d)
node = lambda l, r: H(b"\x01" + l + r)

def root(leaves):
    if len(leaves) == 1: return leaves[0]
    # largest power of two < n
    k = 1 << (len(leaves) - 1).bit_length() - 1
    return node(root(leaves[:k]), root(leaves[k:]))

# audit path for leaf i
def proof(leaves, i):
    if len(leaves) == 1: return []
    k = 1 << (len(leaves) - 1).bit_length() - 1
    return (proof(leaves[:k], i) + [root(leaves[k:])] if i < k
            else proof(leaves[k:], i - k) + [root(leaves[:k])])

def verify(leaf_hash, i, n, path, expected_root):           # RFC 9162 §2.1.3.2
    fn, sn, r = i, n - 1, leaf_hash
    for p in path:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while fn and not fn & 1: fn >>= 1; sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == expected_root

class Log:
    def __init__(self):
        self.sk, self.entries = Ed25519PrivateKey.generate(), []
        self.pk = self.sk.public_key()
    def append(self, account, aik, devlist_hash):
        self.entries.append(f"{account}|{aik}|{devlist_hash}".encode())
    def sth(self, entries=None):
        e = entries if entries is not None else self.entries
        r = root([leaf(x) for x in e]); msg = len(e).to_bytes(8, "big") + r
        return {"size": len(e), "root": r, "sig": self.sk.sign(msg)}
    def lookup(self, account, entries=None):
        e = entries if entries is not None else self.entries
        i = max(j for j,
            x in enumerate(e) if x.startswith(account.encode() + b"|"))
        return e[i], i, proof([leaf(x) for x in e], i)

def client_check(log_pk, sth, entry, i, path):
    try: log_pk.verify(sth["sig"], sth["size"].to_bytes(8, "big") + sth["root"])
    except InvalidSignature: return False
    return verify(leaf(entry), i, sth["size"], path, sth["root"])

if __name__ == "__main__":
    log = Log()
    for n in range(1, 9): log.append(f"user{n}", f"aik{n}", f"dl{n}")
    log.append("bob", "aikBOB", "dlBOB-v3")
    for n in range(9, 14): log.append(f"user{n}", f"aik{n}", f"dl{n}")

    print("── Lookup with inclusion proof ──")
    sth = log.sth(); e, i, path = log.lookup("bob")
    print(
        f"  Alice looks up bob: {e.decode()}  (leaf {i} of {sth['size']}, "
        f"proof of {len(path)} hashes)")
    print(
        f"  inclusion proof + signed tree head verify: "
        f"{client_check(log.pk, sth, e, i, path)}")
    tampered = e.replace(b"aikBOB", b"aikMALLORY")
    print(
        f"  server returns a different key with the same proof: "
        f"{client_check(log.pk, sth, tampered, i, path)}")

    print(
        "── Split view: the server shows Alice a log where bob's key is "
        "Mallory's ──")
    fake = list(log.entries); fake[i] = b"bob|aikMALLORY|dlMALLORY"
    sth_alice = log.sth(fake); e2, i2, p2 = log.lookup("bob", fake)
    print(
        f"  Alice's view verifies on its own: "
        f"{client_check(log.pk, sth_alice, e2, i2, p2)}  → {e2.decode()}")
    # Bob monitors his own entry in the real log
    sth_bob = log.sth()
    print(
        f"  Bob (monitoring) sees his real key in his view: "
        f"{log.lookup('bob')[0].decode()}")
    same_size = sth_alice["size"] == sth_bob["size"]
    print(
        f"  gossip: same size {same_size}, same root "
        f"{sth_alice['root'] == sth_bob['root']} "
        f"→ two signed, conflicting tree heads = PROOF the server equivocated")
