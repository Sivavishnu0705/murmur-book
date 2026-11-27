# pairing.py
"""Listing 17.4 — Python: lab — QR-initiated device pairing over an untrusted
relay with Noise_XXpsk3, a short authentication string (SAS) from the handshake
hash, and the attacks it stops. New device (responder) SHOWS the QR; Alice's
enrolled phone (initiator) SCANS it."""
import hashlib, json, os, warnings
from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from xx_lib import static_key, read

warnings.filterwarnings("ignore")

def qr_for_new_device(new_static_pub):
    """What the new device encodes in its QR code (≈ 100 bytes: fits a small QR
    easily)."""
    return {"v": 1, "rendezvous": os.urandom(8).hex(),      # relay mailbox id
            # one-time pairing secret
            "psk": os.urandom(32).hex(),
            # new device's static key
            "fp": hashlib.sha256(new_static_pub).hexdigest()[:32]}

def conn(initiator, static_priv, qr, use_psk=True):
    name = b"Noise_XXpsk3_25519_ChaChaPoly_SHA256" if use_psk else \
        b"Noise_XX_25519_ChaChaPoly_SHA256"
    c = NoiseConnection.from_name(name)
    c.set_as_initiator() if initiator else c.set_as_responder()
    c.set_keypair_from_private_bytes(Keypair.STATIC, static_priv)
    if use_psk:
        c.set_psks(psk=bytes.fromhex(qr["psk"]))
    # context binding
    c.set_prologue(b"murmur-pairing/v1|" + qr["rendezvous"].encode())
    c.start_handshake()
    return c

def sas(c):
    """6-digit code both screens show: derived from the handshake hash, so it
    covers every message, both static keys and the prologue. Any MITM produces
    two different hashes."""
    d = HKDF(hashes.SHA256(), 4, salt=None,
        info=b"murmur pairing SAS v1").derive(c.get_handshake_hash())
    n = int.from_bytes(d, "big") % 1_000_000
    return f"{n // 1000:03d} {n % 1000:03d}"

class Fail(Exception): pass

def handshake(ini, res, relay=lambda m, i: m, expect_fp=None):
    """Runs XX(psk3) through a relay function that may observe or tamper. If
    expect_fp is given, the initiator checks the responder's static key against
    the QR fingerprint after message 2, BEFORE sending message 3 (which carries
    account data). Returns the static keys learned."""
    try:
        m1 = relay(ini.write_message(b""), 1); read(res, m1)
        m2 = relay(res.write_message(json.dumps({
            "dpop_jkt": "jkt-new-device"}).encode()), 2)
        _, res_static = read(ini, m2)
    except Exception as e:
        raise Fail(type(e).__name__)
    if expect_fp and hashlib.sha256(res_static).hexdigest()[:32] != expect_fp:
        raise Fail("responder static key does not match the QR fingerprint")
    try:
        m3 = relay(ini.write_message(b'{"account":"alice"}'), 3)
        _, ini_static = read(res, m3)
        return res_static, ini_static
    except Exception as e:
        raise Fail(type(e).__name__)

phone_priv, phone_pub = static_key()          # Alice's enrolled phone
new_priv, new_pub = static_key()              # the new tablet

print("── 1. Honest pairing ──")
qr = qr_for_new_device(new_pub)
print(f"  QR payload: {len(json.dumps(qr))} bytes")
phone, tablet = conn(True, phone_priv, qr), conn(False, new_priv, qr)
sizes = []
handshake(phone, tablet, lambda m, i: (sizes.append(len(m)), m)[1],
    expect_fp=qr["fp"])
print(f"  messages {sizes} bytes; tablet key matched the QR fingerprint")
print(
    f"  phone shows {sas(phone)}   tablet shows {sas(tablet)}   → user "
    f"confirms match")

print(
    "── 2. Malicious relay runs a MITM: plain XX, no psk, no fingerprint "
    "check ──")
mal_priv, _ = static_key()
qr2 = qr_for_new_device(new_pub)
phone, tablet = conn(True, phone_priv, qr2, use_psk=False), conn(False,
    new_priv, qr2, use_psk=False)
m_res, m_ini = conn(False, mal_priv, qr2, use_psk=False), conn(True, mal_priv,
    qr2, use_psk=False)
handshake(phone, m_res)
handshake(m_ini, tablet)          # two separate handshakes
print(
    f"  both handshakes complete. phone shows {sas(phone)}   tablet shows "
    f"{sas(tablet)}")
print(
    f"  → if users skip the comparison, the relay sits in the middle; if "
    f"they compare: MISMATCH")

print("── 3. Same MITM against XXpsk3 (relay never saw the QR) ──")
qr3 = qr_for_new_device(new_pub)
phone = conn(True, phone_priv, qr3)
# the relay must guess the psk
guess = dict(qr3, psk=os.urandom(32).hex())
m_res = conn(False, mal_priv, guess)
try:
    handshake(phone, m_res)
    # (fingerprint check off, to isolate the psk)
    print("  MITM completed (!)")
except Fail as e:
    print(
        f"  phone ↔ relay handshake fails: {e} (psk mixed into keys at msg "
        f"3; relay can't decrypt)")

print(
    "── 4. Attacker photographed the QR (knows psk) and impersonates the "
    "tablet ──")
qr4 = qr_for_new_device(new_pub)
phone, fake_tablet = conn(True, phone_priv, qr4), conn(False, mal_priv, qr4)
try:
    handshake(phone, fake_tablet, expect_fp=qr4["fp"])
    print("  impersonation succeeded (!)")
except Fail as e:
    print(f"  phone aborts after message 2, before sending account data: {e}")

print("── 5. Replay of a recorded pairing to Alice's phone ──")
qr5 = qr_for_new_device(new_pub)
recorded = []
handshake(conn(True, phone_priv, qr5), conn(False, new_priv, qr5), lambda m,
    i: (recorded.append(m), m)[1])
# phone starts again (same QR, worst case)
phone = conn(True, phone_priv, qr5)
phone.write_message(b"")                                   # fresh ephemeral e
try:
    read(phone, recorded[1]); print("  replay accepted (!)")
except Exception as e:
    print(
        f"  replayed message 2 rejected: {type(e).__name__} (it was keyed to "
        f"the OLD ephemeral)")

print("── 6. What the relay sees (identity hiding) ──")
qr6 = qr_for_new_device(new_pub)
seen = []
handshake(conn(True, phone_priv, qr6), conn(False, new_priv, qr6), lambda m,
    i: (seen.append(bytes(m)), m)[1])
print(
    f"  static keys visible in any message: phone "
    f"{any(phone_pub in m for m in seen)}, tablet "
    f"{any(new_pub in m for m in seen)}")
