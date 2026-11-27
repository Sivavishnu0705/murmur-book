# hardened.py
"""Listing 31.7 — Python: the fix for red-team finding RT-4 (device-list
rollback), applied to the Chapter 29 client: remember the highest device-list
version accepted for each account and refuse any lower one — checked on the SAME
bytes whose signature is verified. Chapter 20's Contact.Accept (Listing 20.1)
had this check; the Chapter 29 model had lost it."""
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from messenger import Messenger, unb64

class ListRollback(Exception): pass

def list_version(enc):
    """Read the version from the signed encoding: label ‖ account ‖ version
    (u64, big-endian). Every length is checked before slicing, so a short or
    malformed list raises instead of yielding a short slice that int.from_bytes
    would silently read as a small number."""
    def take(i, n, what):
        if n < 0 or i + n > len(enc):
            raise ValueError(f"device list truncated in {what}")
        return enc[i:i + n], i + n
    i = 0
    for what in ("label", "account"):
        ln, i = take(i, 4, what + " length")
        _, i = take(i, int.from_bytes(ln, "big"), what)
    v, _ = take(i, 8, "version")
    return int.from_bytes(v, "big")

class HardenedMessenger(Messenger):
    def refresh_contact(self, account):
        row = self.db.execute(
            "SELECT aik, trust, version FROM contacts WHERE account=?",
            (account,)).fetchone()
        st, dl = self.call("GET", f"/v1/devicelist/{account}")
        enc, sig = unb64(dl["encoded"]), unb64(dl["signature"])
        aik, trust, seen = (row[0], row[1], row[2] or 0) if row else (None,
            None, 0)
        aik_changed = False
        try:
            if aik is None: raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(aik).verify(sig, enc)
        except InvalidSignature:
            new_aik = unb64(self.call("GET", f"/v1/aik/{account}")[1]["aik"])
            Ed25519PublicKey.from_public_bytes(new_aik).verify(sig, enc)
            if aik is None: trust = "unverified"
            elif new_aik != aik:
                trust = "changed_from_verified" if trust in ("verified",
                    "changed_from_verified") else "changed_unverified"
            aik_changed, aik = aik is not None and new_aik != aik, new_aik
        devices = self._parse_list(enc, account)
        v = list_version(enc)
        # The new check. Versions are per AIK: a NEW AIK (reinstall, RT-7)
        # restarts at v1 and is handled by the trust-change path above; under
        # the SAME AIK the version never goes back.
        if v < seen and not aik_changed:
            raise ListRollback(
                f"{account}'s device list went back from v{seen} to v{v}")
        with self.store.tx():
            self.db.execute(
                "INSERT INTO contacts (account, aik, trust, devices, "
                "version) VALUES (?,?,?,?,?) "
                "ON CONFLICT(account) DO UPDATE SET aik=excluded.aik, "
                "trust=excluded.trust, "
                "devices=excluded.devices, version=excluded.version",
                (account, aik, trust, json.dumps({d: k.hex() for d,
                k in devices.items()}), v))
        return devices
