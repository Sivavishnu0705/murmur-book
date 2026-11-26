# Listing 10.3 — Python: decode and inspect a JWT; show why "alg: none" and algorithm
# confusion work against a naive verifier, and how a strict verifier rejects both.
import base64, hashlib, hmac, json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def inspect(token: str) -> None:
    """Decoding is NOT verifying: anyone can read (and write) these fields."""
    h, c, _ = token.split(".")
    print("header :", json.loads(b64d(h)))
    print("claims :", json.loads(b64d(c)))

def sign_es256(key, header: dict, claims: dict) -> str:
    signing_input = b64e(json.dumps(header).encode()) + "." + b64e(json.dumps(claims).encode())
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big"))  # raw r‖s

# ⚠️ INSECURE — the classic bug: the TOKEN chooses the algorithm.
def naive_verify(token: str, key_material: bytes, pub) -> dict:
    h, c, sig = token.split(".")
    alg = json.loads(b64d(h))["alg"]
    if alg == "none":
        pass                                                   # "unsigned token": accepted!
    elif alg == "HS256":                                       # key_material used as HMAC secret
        expect = hmac.new(key_material, f"{h}.{c}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expect, b64d(sig)):
            raise ValueError("bad HMAC")
    elif alg == "ES256":
        raw = b64d(sig)
        pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))
    return json.loads(b64d(c))

# ✓ The verifier decides: one allowed algorithm per key, fixed in configuration.
def strict_verify(token: str, pub, *, iss: str, aud: str, now: int) -> dict:
    h, c, sig = token.split(".")
    if json.loads(b64d(h)).get("alg") != "ES256":
        raise ValueError("algorithm not allowed")
    raw = b64d(sig)
    if len(raw) != 64:
        raise ValueError("bad signature length")
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
               f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))
    claims = json.loads(b64d(c))
    if claims.get("iss") != iss or claims.get("aud") != aud or claims.get("exp", 0) < now:
        raise ValueError("claims rejected")
    return claims

if __name__ == "__main__":
    import time
    now = int(time.time())
    key = ec.generate_private_key(ec.SECP256R1()); pub = key.public_key()
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claims = {"iss": "https://auth.murmur.example", "aud": "https://api.murmur.example",
              "sub": "alice", "scope": "messages:send", "exp": now + 300}
    good = sign_es256(key, {"alg": "ES256", "typ": "at+jwt", "kid": "k1"}, claims)
    inspect(good)

    evil_claims = {**claims, "sub": "mallory", "scope": "admin:all"}
    none_tok = b64e(json.dumps({"alg": "none"}).encode()) + "." + b64e(json.dumps(evil_claims).encode()) + "."
    hs_in = b64e(json.dumps({"alg": "HS256"}).encode()) + "." + b64e(json.dumps(evil_claims).encode())
    hs_tok = hs_in + "." + b64e(hmac.new(pub_pem, hs_in.encode(), hashlib.sha256).digest())  # public key!

    print()
    for name, tok in [("genuine ES256", good), ("alg: none", none_tok), ("HS256 w/ public key", hs_tok)]:
        try:
            got = naive_verify(tok, pub_pem, pub)["sub"]; naive = f"ACCEPTED (sub={got})"
        except (ValueError, InvalidSignature) as e:
            naive = f"rejected ({type(e).__name__})"
        try:
            strict = f"ACCEPTED (sub={strict_verify(tok, pub, iss=claims['iss'], aud=claims['aud'], now=now)['sub']})"
        except (ValueError, InvalidSignature) as e:
            strict = f"rejected ({e or type(e).__name__})"
        print(f"{name:20}  naive: {naive:28}  strict: {strict}")
