# messenger.py
"""Listing 29.2 — Python: Murmur's one-to-one messaging pipelines — an
executable model of the Kotlin and Swift code in this chapter, on the Chapter 28
storage model (SQLCipher):
  send: encrypt → persist (state + outbox + send log, ONE transaction) → send →
  delete outbox row receive: BEGIN IMMEDIATE → dedupe → load state → decrypt →
  persist (state + inbox) → COMMIT → ack
Every envelope is sealed (sender certificate inside, Ch 21); the route differs:
authenticated for a first contact, delivery token afterwards."""
import base64, hashlib, json, os, time, uuid
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
    Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, InvalidTag
import ratchet, x3dh, xeddsa, safety, murmur_pb2 as pb
from murmur_client import b64, unb64, pad, unpad, encode_device_list
from stored_device import StoredDevice

PQ_INFO = b"Murmur_CURVE25519_SHA-256_ML-KEM-1024"
# accept sender certificates up to 1 h past expiry (clock skew)
CERT_SKEW = 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (peer TEXT PRIMARY KEY, account TEXT,
    remote_ik BLOB, ad BLOB, state TEXT, created REAL,
    -- pending_pre: resend PreKeyMessage until the peer replies
    pending_pre BLOB, base_key BLOB);
CREATE TABLE IF NOT EXISTS archived_sessions (peer TEXT, remote_ik BLOB,
    ad BLOB, state TEXT, archived REAL);
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, route TEXT,
    account TEXT, content BLOB, envelopes TEXT);
CREATE TABLE IF NOT EXISTS send_log (peer TEXT, header BLOB, content BLOB,
    at REAL, PRIMARY KEY (peer, header));
CREATE TABLE IF NOT EXISTS processed (guid BLOB PRIMARY KEY, at REAL);
CREATE TABLE IF NOT EXISTS seen_headers (peer TEXT, h BLOB,
    PRIMARY KEY (peer, h));
CREATE TABLE IF NOT EXISTS inbox (client_message_id BLOB PRIMARY KEY,
    sender TEXT, conversation TEXT, text TEXT,
    attachments TEXT, server_ts REAL, outgoing INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS contacts (account TEXT PRIMARY KEY, aik BLOB,
    trust TEXT, token BLOB, devices TEXT, version INTEGER);
CREATE TABLE IF NOT EXISTS failures (peer TEXT, header BLOB, at REAL);
"""

# ── Double Ratchet state ⇄ JSON (stored inside SQLCipher; never in plain files)
# ──
def dump_state(r):
    h = lambda b: b.hex() if b else None
    return json.dumps({"DHs": r.DHs.k.private_bytes_raw().hex(),
        "DHr": h(r.DHr), "RK": h(r.RK), "CKs": h(r.CKs),
        "CKr": h(r.CKr), "Ns": r.Ns, "Nr": r.Nr, "PN": r.PN,
        "skipped": [[k[0].hex(), k[1], v.hex()] for k,
        v in r.MKSKIPPED.items()]})

def load_state(s):
    d, u = json.loads(s), lambda x: bytes.fromhex(x) if x else None
    r = ratchet.Ratchet(); r.DHs = ratchet.DHPair(bytes.fromhex(d["DHs"]))
    r.DHr, r.RK, r.CKs, r.CKr = u(d["DHr"]), u(d["RK"]), u(d["CKs"]), u(
        d["CKr"])
    r.Ns, r.Nr, r.PN = d["Ns"], d["Nr"], d["PN"]
    r.MKSKIPPED = {(bytes.fromhex(a), n): bytes.fromhex(m) for a, n,
        m in d["skipped"]}
    return r

def framed(label, *fields):                               # Listing 24.2
    out = len(label).to_bytes(2, "big") + label
    for f in fields: out += len(f).to_bytes(4, "big") + f
    return out

class Edge29:
    """Wraps the Chapter 27 Edge client and remembers the server's Date header
    (for clock skew)."""
    def __init__(self, edge): self.inner, self.last_date = edge, None
    def request(self, *a, **kw):
        from email.utils import parsedate_to_datetime
        st, js, h = self.inner.request(*a, **kw)
        if h.get("Date"):
            self.last_date = parsedate_to_datetime(h["Date"]).timestamp()
        return st, js, h

class Crash(Exception):
    """Injected process death at a named point (the lab's crash tests)."""

class KeyChangeBlocked(Exception): pass

class Messenger(StoredDevice):
    def __init__(self, *a, cert_pub=None, **kw):
        super().__init__(*a, **kw)
        self.store.db.executescript(SCHEMA)
        # wait for the other process's transaction
        self.store.db.execute("PRAGMA busy_timeout = 10000")
        self.cert_pub, self.cert, self.clock_offset = cert_pub, None, 0.0
        self.token_for_replies = os.urandom(16)

    @property
    def db(self): return self.store.db
    def peer_key(self, account, device): return f"{account}/{device}"

    # ───────────── clock skew: DPoP iat uses server time learned from the Date
    # header ─────────────
    def proof(self, method, url, at=None):
        real = time.time
        time.time = lambda: real() + self.clock_offset
        try: return super().proof(method, url, at)
        finally: time.time = real

    def call(self, method, path, body=None, _skew_retry=False, **kw):
        st, js = super().call(method, path, body, **kw)
        if st == 401 and "error=\"invalid_token\"" in js.get("www_authenticate",
            "") and "revoked" not in js.get("www_authenticate", ""):
            # stand-in for the refresh flow (Listing 11.4)
            self.login(phr=True)
            st, js = super().call(method, path, body, **kw)
        if st == 401 and "invalid_dpop_proof" in js.get("www_authenticate",
            "") and not _skew_retry:
            # Date header of that response
            server_now = self.edge.last_date
            if server_now and abs(server_now - (
                time.time() + self.clock_offset)) > 30:
                # adjust once, then retry
                self.clock_offset = server_now - time.time()
                return self.call(method, path, body, _skew_retry=True, **kw)
        return st, js

    # ─────────── contacts, device lists, trust (Ch 20 §20.3–20.6) ─────────────
    def refresh_contact(self, account):
        """Fetch and VERIFY the account's device list. Returns {device: identity
        key}."""
        row = self.db.execute("SELECT aik, trust FROM contacts WHERE account=?",
            (account,)).fetchone()
        st, dl = self.call("GET", f"/v1/devicelist/{account}")
        enc, sig = unb64(dl["encoded"]), unb64(dl["signature"])
        aik, trust = (row[0], row[1]) if row else (None, None)
        try:
            if aik is None: raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(aik).verify(sig, enc)
        except InvalidSignature:
            # production: + KT proof
            new_aik = unb64(self.call("GET", f"/v1/aik/{account}")[1]["aik"])
            # must verify under SOME aik
            Ed25519PublicKey.from_public_bytes(new_aik).verify(sig, enc)
            # first contact (TOFU + KT)
            if aik is None: trust = "unverified"
            elif new_aik != aik:
                trust = "changed_from_verified" if trust in ("verified",
                    "changed_from_verified") else "changed_unverified"
            aik = new_aik
        devices = self._parse_list(enc, account)
        with self.store.tx():
            self.db.execute(
                "INSERT INTO contacts (account, aik, trust, devices, "
                "version) VALUES (?,?,?,?,?) "
                "ON CONFLICT(account) DO UPDATE SET aik=excluded.aik, "
                "trust=excluded.trust, devices=excluded.devices",
                (account, aik, trust, json.dumps({d: k.hex() for d,
                k in devices.items()}), 0))
        return devices

    @staticmethod
    def _parse_list(enc, account=None):
        """Strict parse of Ch 20's canonical encoding, the same rules as the
        server's parseDeviceList (Listing 27.4): every length checked against
        the remaining bytes, the right label and account, at most 8 devices,
        strictly sorted IDs, no trailing bytes. (The AIK signature has already
        been verified over these exact bytes.)"""
        i = 0
        def take(n):
            nonlocal i
            if n < 0 or i + n > len(enc):
                raise ValueError("malformed device list")
            v = enc[i:i + n]; i += n; return v
        u32 = lambda: int.from_bytes(take(4), "big")
        s = lambda: take(u32())
        if s() != b"murmur device list v1":
            raise ValueError("malformed device list")
        acct = s().decode()
        if account is not None and acct != account:
            raise ValueError("device list for another account")
        take(8)                                             # version
        n = u32()
        if n > 8: raise ValueError("malformed device list")
        out, prev = {}, None
        for _ in range(n):
            d = s().decode(); ik = take(32); s(); take(8)
            # sorted, no dups
            if prev is not None and d <= prev: raise ValueError(
                "malformed device list")
            out[d], prev = ik, d
        if i != len(enc): raise ValueError("malformed device list")
        return out

    def trust(self, account):
        r = self.db.execute("SELECT trust FROM contacts WHERE account=?",
            (account,)).fetchone()
        return r[0] if r else None

    def safety_number(self, account):
        my_aik = self.store.identity("account_identity")[0]
        their = self.db.execute("SELECT aik FROM contacts WHERE account=?",
            (account,)).fetchone()[0]
        return safety.safety_number(my_aik, self.account.encode(), their,
            account.encode())

    def qr(self, account):
        my_aik = self.store.identity("account_identity")[0]
        their = self.db.execute("SELECT aik FROM contacts WHERE account=?",
            (account,)).fetchone()[0]
        return safety.qr_payload(my_aik, self.account.encode(), their,
            account.encode())

    def scan_qr(self, account, scanned):
        """Verification: the payload shown on the other phone must equal ours,
        byte for byte."""
        ok = scanned == self.qr(account)
        if ok:
            with self.store.tx():
                self.db.execute(
                    "UPDATE contacts SET trust='verified' WHERE account=?",
                    (account,))
        return ok

    def accept_key_change(self, account):
        with self.store.tx():
            self.db.execute(
                "UPDATE contacts SET trust='changed_unverified' WHERE "
                "account=?", (account,))

    # ───────────── sessions ─────────────
    def _session(self, peer):
        return self.db.execute(
            "SELECT state, ad, remote_ik, pending_pre, base_key FROM "
            "sessions WHERE peer=?", (peer,)).fetchone()

    def _new_session(self, account, device, ik_expected):
        """PQXDH initiator (Ch 18): fetch the bundle, verify it against the
        VERIFIED device list."""
        st, b = self.call("GET", f"/v1/keys/bundle/{device}")
        ik, spk, pq = unb64(b["identity_key"]), unb64(
            b["signed_prekey"]["pub"]), b["pq_prekey"]
        pqpk = unb64(pq["pub"])
        if ik != ik_expected:
            raise ValueError(
                "bundle identity key is not the one in the signed device list")
        if not (xeddsa.verify(ik, b"\x05" + spk,
            unb64(b["signed_prekey"]["sig"])) and
            xeddsa.verify(ik, b"\x08" + pqpk,
            unb64(pq["sig"]))): raise ValueError("bundle signature invalid")
        ek = x3dh.KeyPair()
        ss, kem_ct = mlkem.MLKEM1024PublicKey.from_public_bytes(
            pqpk).encapsulate()
        km = x3dh.DH(self.ik, spk) + x3dh.DH(ek, ik) + x3dh.DH(ek, spk)
        opk = b.get("one_time_prekey")
        if opk: km += x3dh.DH(ek, unb64(opk["pub"]))
        sk = HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
            info=PQ_INFO).derive(x3dh.F + km + ss)
        pre = pb.PreKeyMessage(suite=0x0002, identity_key=self.ik.pub,
            ephemeral_key=ek.pub,
            signed_prekey_id=b["signed_prekey"]["id"], pq_prekey_id=pq["id"],
            kem_ciphertext=kem_ct)
        if opk: pre.one_time_prekey_id = opk["id"]
        return ratchet.Ratchet.init_alice(sk,
            spk), x3dh.encode(self.ik.pub) + x3dh.encode(ik), ik, pre

    # ───────────── send pipeline (Fig 29.1) ─────────────
    def _sender_cert(self):
        if not self.cert or self.cert["expires_unix"] - time.time() < 3600:
            self.cert = self.call("GET", "/v1/sender-certificate")[1]
        c = self.cert
        return pb.SenderCertificate(account=c["account"], device=c["device"],
            identity_key=unb64(c["identity_key"]),
            expires_unix=c["expires_unix"],
            signature=unb64(c["signature"])).SerializeToString()

    def _seal(self, recipient_device, recipient_ik, inner):
        cert = self._sender_cert()
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()
        k = HKDF(hashes.SHA256(), 32, salt=eph_pub + recipient_ik,
            info=b"murmur sealed sender v1").derive(
            eph.exchange(X25519PublicKey.from_public_bytes(recipient_ik)))
        # 160-byte buckets
        body = pad(len(cert).to_bytes(2, "big") + cert + inner)
        # A zero nonce is safe ONLY because this key is used once: every _seal
        # call makes a fresh ephemeral X25519 key, so DH(eph, IK) and the HKDF
        # output (salt eph ‖ IK) are new each time. Never cache `eph` or `k`
        # across envelopes (Ch 2 §2.11's cached-ephemeral bug).
        sealed = pb.SealedEnvelope(ephemeral_key=eph_pub,
            ciphertext=AESGCM(k).encrypt(b"\x00" * 12, body, None))
        return pb.Envelope(version=1, type=pb.SEALED_SENDER,
            recipient_device=recipient_device,
            content=sealed.SerializeToString()).SerializeToString()

    def _encrypt_for(self, account, device, ik, content, now):
        """Inside the caller's transaction: advance the ratchet for one device,
        log the header."""
        peer = self.peer_key(account, device)
        row, pre = self._session(peer), None
        if row:
            r, ad = load_state(row[0]), row[1]
            # no reply yet: keep sending PreKeyMessages
            if row[3]: pre = pb.PreKeyMessage.FromString(row[3])
            base = row[4]
        else:
            r, ad, _, pre = self._pending_sessions.pop(peer); base = None
        hdr, ct = r.encrypt(pad(content), ad)
        msg = pb.RatchetMessage(header=hdr, ciphertext=ct)
        if pre is not None:
            # the PreKeyMessage fields, without a message
            pending = pre.SerializeToString()
            pre.message.CopyFrom(msg)
            inner = pb.Envelope(version=1, type=pb.PREKEY_MESSAGE,
                recipient_device=device, content=pre.SerializeToString())
        else:
            pending = None
            inner = pb.Envelope(version=1, type=pb.RATCHET_MESSAGE,
                recipient_device=device, content=msg.SerializeToString())
        self.db.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?)", (peer,
            account, ik, ad, dump_state(r), now, pending, base))
        self.db.execute("INSERT OR REPLACE INTO send_log VALUES (?,?,?,?)",
            (peer, hdr, content, now))
        return self._seal(device, ik, inner.SerializeToString())

    def send(self, account, text, attachments=(), crash=None, now=None):
        """Encrypt for every verified device of `account` and every other device
        of our own account (sync), persist, then deliver from the outbox."""
        now = now or time.time()
        if self.trust(account) == "changed_from_verified":
            raise KeyChangeBlocked(
                f"{account}'s safety number changed since you verified it")
        cmid = os.urandom(16)
        dm = pb.DataMessage(conversation_id=account, sent_at_ms=int(now * 1000),
            text=text, client_message_id=cmid)
        for a in attachments: dm.attachments.append(a)
        to_them = pb.Content(data=dm,
            delivery_token=self.token_for_replies).SerializeToString()
        to_me = pb.Content(sync=pb.SyncMessage(sent=dm,
            destination_account=account)).SerializeToString()
        targets = {account: (self._devices(account), to_them),
            self.account: (self._own_other_devices(), to_me)}
        # Network first (bundles for devices without a session), crypto and
        # persistence second.
        self._pending_sessions = {}
        for acct, (devs, _) in targets.items():
            for d, ik in devs.items():
                if not self._session(self.peer_key(acct, d)):
                    self._pending_sessions[self.peer_key(acct,
                        d)] = self._new_session(acct, d, ik)
        ids = []
        # ONE transaction for all of it
        with self.store.tx():
            for acct, (devs, content) in targets.items():
                if not devs: continue
                envs = {d: b64(self._encrypt_for(acct, d, ik, content,
                    now)) for d, ik in devs.items()}
                if crash == "after_encrypt_before_commit": raise Crash(crash)
                oid = str(uuid.uuid4())
                ids.append(oid)          # the outbox id IS the idempotency key
                self.db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)", (oid,
                    self._route(acct), acct, content, json.dumps(envs)))
        self.db.execute("INSERT OR IGNORE INTO inbox VALUES (?,?,?,?,?,?,1)",
            (cmid, self.account, account, text, "[]", now))
        if crash == "after_commit_before_send": raise Crash(crash)
        return cmid, self.flush_outbox()

    def _route(self, account):
        if account == self.account: return "identified"
        r = self.db.execute("SELECT token FROM contacts WHERE account=?",
            (account,)).fetchone()
        return "sealed" if r and r[0] else "identified"

    def _devices(self, account):
        r = self.db.execute("SELECT devices FROM contacts WHERE account=?",
            (account,)).fetchone()
        if not r or not r[0]: return self.refresh_contact(account)
        return {d: bytes.fromhex(k) for d, k in json.loads(r[0]).items()}

    def _own_other_devices(self):
        return {d: k for d,
            k in self._devices(self.account).items() if d != self.device_id}

    def flush_outbox(self):
        """Deliver every outbox row. Safe to run any number of times: each row
        has one key."""
        results = []
        for oid, route, account, content, envs in self.db.execute(
            "SELECT * FROM outbox").fetchall():
            envs = json.loads(envs)
            for _ in range(3):
                body = {"recipient_account": account,
                    "envelopes": [{"device": d, "body": e} for d,
                    e in envs.items()]}
                if route == "sealed":
                    token = self.db.execute(
                        "SELECT token FROM contacts WHERE account=?", (account,
                        )).fetchone()[0]
                    st, js, _ = self.edge.request("api", "POST", "/v1/sealed",
                        body, {"Murmur-Delivery-Token": b64(token)})
                    # token changed (e.g. reinstall): send identified
                    if st == 401:
                        route = "identified"; continue
                # key = H(outbox id ‖ exact body): a retry of the same bytes is
                # deduplicated,
                else:
                        # a repaired (different) body is a different request
                        # with a different key
                    idem = hashlib.sha256((oid + json.dumps(body,
                        sort_keys=True)).encode()).hexdigest()[:32]
                    st, js = self.call("POST", "/v1/messages", body, idem=idem)
                if st == 409 and js.get("code") == "DEVICE_MISMATCH":
                    # §29.3
                    envs = self._repair_fanout(oid, account, content, envs)
                    continue
                break
            if st == 202:
                with self.store.tx():
                    self.db.execute("DELETE FROM outbox WHERE id=?", (oid,))
            results.append((account, route, st, len(envs)))
        return results

    def _repair_fanout(self, oid, account, content, envs):
        """The recipient's device set changed mid-send. Keep the ciphertexts
        already made for devices that remain (they were never delivered, so
        reusing them is safe, and the ratchet must NOT be advanced again for
        them); encrypt for new devices; drop removed ones."""
        devs = self.refresh_contact(account)
        if account == self.account:
            devs = {d: k for d, k in devs.items() if d != self.device_id}
        elif self.trust(account) == "changed_from_verified":
            raise KeyChangeBlocked(
                f"{account}'s safety number changed since you verified it")
        now = time.time(); self._pending_sessions = {}
        for d, ik in devs.items():
            if d not in envs and not self._session(self.peer_key(account, d)):
                self._pending_sessions[self.peer_key(account,
                    d)] = self._new_session(account, d, ik)
        with self.store.tx():
            new = {d: envs[d] for d in devs if d in envs}
            for d, ik in devs.items():
                if d not in envs:
                    new[d] = b64(self._encrypt_for(account, d, ik, content,
                        now))
            self.db.execute("UPDATE outbox SET envelopes=? WHERE id=?",
                (json.dumps(new), oid))
        self.fanout_repairs = getattr(self, "fanout_repairs",
            []) + [(sorted(set(envs) - set(devs)),
            sorted(set(devs) - set(envs)))]
        return new

    # ───────────── receive pipeline (Fig 29.2) ─────────────
    def _unseal(self, env_bytes):
        env = pb.Envelope.FromString(env_bytes)
        if env.version != 1 or env.type != pb.SEALED_SENDER:
            raise ValueError("UNSUPPORTED")
        s = pb.SealedEnvelope.FromString(env.content)
        k = HKDF(hashes.SHA256(), 32, salt=s.ephemeral_key + self.ik.pub,
            info=b"murmur sealed sender v1").derive(
            X25519PrivateKey.from_private_bytes(self.ik.priv).exchange(
            X25519PublicKey.from_public_bytes(s.ephemeral_key)))
        p = unpad(AESGCM(k).decrypt(b"\x00" * 12, s.ciphertext, None))
        n = int.from_bytes(p[:2], "big")
        cert = pb.SenderCertificate.FromString(p[2:2 + n])
        msg = framed(b"murmur sender cert v1", cert.account.encode(),
            cert.device.encode(), cert.identity_key,
            cert.expires_unix.to_bytes(8, "big"))
        # raises InvalidSignature
        self.cert_pub.verify(cert.signature, msg)
        if time.time() + self.clock_offset > cert.expires_unix + CERT_SKEW:
            raise ValueError("sender certificate expired")
        return cert, pb.Envelope.FromString(p[2 + n:])

    def _listed(self, cert):
        """True if cert's (device, identity key) is in the sender's verified
        device list."""
        r = self.db.execute("SELECT devices FROM contacts WHERE account=?",
            (cert.account,)).fetchone()
        if not r or not r[0]: return False
        return json.loads(r[0]).get(cert.device) == cert.identity_key.hex()

    def _responder_session(self, pre):
        spk = x3dh.KeyPair(self.store.get("spk", pre.signed_prekey_id))
        seed = self.store.get("pqopk",
            pre.pq_prekey_id) or self.store.get("pqlr", pre.pq_prekey_id)
        ss = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed).decapsulate(
            pre.kem_ciphertext)
        km = x3dh.DH(spk, pre.identity_key) + x3dh.DH(self.ik,
            pre.ephemeral_key) + x3dh.DH(spk, pre.ephemeral_key)
        if pre.HasField("one_time_prekey_id"):
            km += x3dh.DH(x3dh.KeyPair(self.store.get("opk",
                pre.one_time_prekey_id)), pre.ephemeral_key)
        sk = HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
            info=PQ_INFO).derive(x3dh.F + km + ss)
        return ratchet.Ratchet.init_bob(sk,
            ratchet.DHPair(spk.priv)), x3dh.encode(
            pre.identity_key) + x3dh.encode(self.ik.pub)

    def receive(self, crash=None, order=None, naive=False, limit=None):
        st, q = self.call("GET", "/v1/messages")
        envs = q["envelopes"][:limit] if limit else q["envelopes"]
        if order: envs = order(envs)
        done, out, resets = [], [], []
        # network work BEFORE any transaction:
        for e in envs:
            # learn devices we have not seen in a signed list
            try:
                cert, _ = self._unseal(unb64(e["body"]))
                if self._listed(cert) is False:
                    self.refresh_contact(cert.account)
            except Exception:
                # _process reports the problem
                pass
        for e in envs:
            guid, body = unb64(e["guid"]), unb64(e["body"])
            r = self._process_naive(guid,
                body) if naive else self._process(guid, body, crash, resets)
            if r is not None: out.append(r)
            done.append(e["guid"])
            if crash == "after_commit_before_ack": raise Crash(crash)
        # ONLY after every commit
        if done: self.call("POST", "/v1/messages/ack", {"guids": done})
        for peer, account, device, headers in resets:
            self._request_reset(account, device, headers)
        return out

    def _process(self, guid, body, crash, resets):
        # BEGIN IMMEDIATE: one writer at a time
        with self.store.tx():
            if self.db.execute("SELECT 1 FROM processed WHERE guid=?", (guid,
                )).fetchone():
                # redelivery after a crash, or the NSE got it
                return None
            self.db.execute("INSERT INTO processed VALUES (?,?)", (guid,
                time.time()))
            try:
                cert, inner = self._unseal(body)
            except (InvalidTag, InvalidSignature, ValueError):
                return ("rejected", "unsealing or sender certificate failed")
            peer = self.peer_key(cert.account, cert.device)
            # the server signs certificates, so a malicious
            if not self._listed(cert):
                # one could invent devices
                return ("rejected",
                    "sender device not in the sender's AIK-signed device list")
            if inner.type == pb.PREKEY_MESSAGE:
                pre = pb.PreKeyMessage.FromString(inner.content)
                rm = pre.message
            else:
                pre, rm = None, pb.RatchetMessage.FromString(inner.content)
            hh = hashlib.sha256(rm.header).digest()
            if self.db.execute(
                "SELECT 1 FROM seen_headers WHERE peer=? AND h=?", (peer,
                hh)).fetchone():
                # never a reset trigger
                return ("duplicate", f"replayed header from {peer} ignored")
            candidates, cur = [], self._session(peer)
            if pre is not None:
                # rule V1
                if pre.suite != 0x0002: return ("rejected", "UNSUPPORTED_SUITE")
                if pre.identity_key != cert.identity_key:
                    return ("rejected", "certificate ≠ session identity")
                # not a repeat of the session we have
                if not (cur and cur[4] == pre.ephemeral_key):
                    candidates.append(("new",
                        ) + self._responder_session(pre) + (pre.identity_key,))
            if cur and cur[2] == cert.identity_key:
                candidates.append(("sessions", load_state(cur[0]), cur[1],
                    cur[2]))
            for st_, ad, rik in self.db.execute(
                "SELECT state, ad, remote_ik FROM archived_sessions WHERE "
                "peer=?", (peer,)):
                if rik == cert.identity_key:
                    candidates.append(("archived_sessions", load_state(st_), ad,
                        rik))
            for kind, r, ad, rik in candidates:
                try:
                    content = pb.Content.FromString(unpad(r.decrypt(rm.header,
                        rm.ciphertext, ad)))
                except (InvalidTag, ValueError):
                    continue
                # rolls back everything
                if crash == "after_decrypt_before_commit": raise Crash(crash)
                base, pending = (cur[4], None) if cur else (None, None)
                # the peer started a new session
                if kind == "new":
                    if cur:
                        self.db.execute(
                            "INSERT INTO archived_sessions VALUES (?,?,?,?,?)",
                            (peer, cur[2], cur[1], cur[0], time.time()))
                    base = pre.ephemeral_key
                    for k, i in (("opk",
                        pre.one_time_prekey_id if pre.HasField(
                        "one_time_prekey_id") else None),
                        ("pqopk", pre.pq_prekey_id)):
                        if i is not None:
                            self.db.execute(
                                "DELETE FROM prekeys WHERE kind=? AND id=?", (k,
                                i))
                if kind == "archived_sessions":
                    self.db.execute(
                        "UPDATE archived_sessions SET state=? WHERE peer=? "
                        "AND remote_ik=? AND ad=?", (dump_state(r), peer, rik,
                        ad))
                # a reply arrived: stop sending PreKeyMessages
                else:
                    self.db.execute(
                        "INSERT OR REPLACE INTO sessions VALUES "
                        "(?,?,?,?,?,?,?,?)",
                        (peer, cert.account, rik, ad, dump_state(r),
                        time.time(), pending, base))
                self.db.execute("INSERT INTO seen_headers VALUES (?,?)", (peer,
                    hh))
                return self._deliver_content(cert, content, resets)
            # Nothing decrypts: record it, and ask for a new session
            # (rate-limited) after COMMIT.
            self.db.execute("INSERT INTO failures VALUES (?,?,?)", (peer,
                rm.header, time.time()))
            recent = self.db.execute(
                "SELECT count(*) FROM failures WHERE peer=? AND at > ?", (peer,
                time.time() - 3600)).fetchone()[0]
            if recent <= 3:
                resets.append((peer, cert.account, cert.device, [rm.header]))
            return ("undecryptable",
                f"from {peer}: session reset requested" if recent <= 3 else
                "rate-limited")

    def _deliver_content(self, cert, content, resets):
        if content.delivery_token:
            self.db.execute(
                "INSERT INTO contacts (account, token) VALUES (?,?) ON "
                "CONFLICT(account) DO UPDATE SET token=excluded.token",
                (cert.account, content.delivery_token))
        which = content.WhichOneof("body")
        if which == "data":
            d = content.data
            self.db.execute(
                "INSERT OR IGNORE INTO inbox VALUES (?,?,?,?,?,?,0)",
                (d.client_message_id, cert.account, cert.account, d.text,
                json.dumps([a.cdn_id for a in d.attachments]), time.time()))
            self.last_attachments = list(d.attachments)
            return ("message", cert.account, cert.device, d.text)
        if which == "sync":
            d = content.sync.sent
            self.db.execute(
                "INSERT OR IGNORE INTO inbox VALUES (?,?,?,?,?,?,1)",
                (d.client_message_id, self.account,
                content.sync.destination_account, d.text, "[]", time.time()))
            return ("sync", content.sync.destination_account, cert.device,
                d.text)
        if which == "control" and content.control.kind == \
            pb.SessionControl.RESET_REQUEST:
            self.pending_resends = getattr(self, "pending_resends",
                []) + [(cert.account, cert.device,
                list(content.control.failed_headers))]
            return ("reset-request", cert.account, cert.device,
                f"{len(content.control.failed_headers)} message(s) to resend")
        return ("other", which)

    # ───────────── session reset (§29.7) ─────────────
    def _request_reset(self, account, device, headers):
        """A NEW session to the peer device whose message we could not decrypt,
        carrying the failed headers so the peer can re-send those messages from
        its send log."""
        ik = self._devices(account).get(device)
        peer = self.peer_key(account, device)
        self._pending_sessions = {peer: self._new_session(account, device, ik)}
        content = pb.Content(control=pb.SessionControl(
            kind=pb.SessionControl.RESET_REQUEST, failed_headers=headers),
            delivery_token=self.token_for_replies).SerializeToString()
        with self.store.tx():
            old = self._session(peer)
            if old:
                self.db.execute(
                    "INSERT INTO archived_sessions VALUES (?,?,?,?,?)", (peer,
                    old[2], old[1], old[0], time.time()))
            self.db.execute("DELETE FROM sessions WHERE peer=?", (peer,))
            env = b64(self._encrypt_for(account, device, ik, content,
                time.time()))
            self.db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), "identified", account, content,
                json.dumps({device: env})))
        self.flush_outbox()

    def handle_resends(self):
        """Re-encrypt logged messages on the NEW session the peer started (24 h
        send log)."""
        done = []
        for account, device, headers in getattr(self, "pending_resends", []):
            peer = self.peer_key(account, device)
            ik = self._devices(account)[device]
            with self.store.tx():
                for h in headers:
                    row = self.db.execute(
                        "SELECT content FROM send_log WHERE peer=? AND "
                        "header=? AND at > ?",
                        (peer, h, time.time() - 86400)).fetchone()
                    if not row: continue
                    env = b64(self._encrypt_for(account, device, ik, row[0],
                        time.time()))
                    self.db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)",
                        (str(uuid.uuid4()), "identified", account, row[0],
                        json.dumps({device: env})))
                    done.append(h)
        self.pending_resends = []
        self.flush_outbox()
        return len(done)

    # ───────────── ⚠️ INSECURE comparison: state cached in memory, no
    # IMMEDIATE, ack first ─────────────
    def _process_naive(self, guid, body):
        cert, inner = self._unseal(body)
        peer = self.peer_key(cert.account, cert.device)
        if not hasattr(self, "_cache"): self._cache = {}
        # read once, outside any transaction
        if peer not in self._cache:
            row = self._session(peer)
            self._cache[peer] = (load_state(row[0]), row[1])
        r, ad = self._cache[peer]
        rm = pb.RatchetMessage.FromString(inner.content)
        try:
            content = pb.Content.FromString(unpad(r.decrypt(rm.header,
                rm.ciphertext, ad)))
        except (InvalidTag, ValueError):
            return ("undecryptable", peer)
        self.db.execute("UPDATE sessions SET state=? WHERE peer=?",
            (dump_state(r), peer))
        self.db.execute("INSERT OR IGNORE INTO inbox VALUES (?,?,?,?,?,?,0)",
            (content.data.client_message_id, cert.account, cert.account,
            content.data.text, "[]", time.time()))
        return ("message", cert.account, cert.device, content.data.text)

# ───────────── sharing one device between processes (the app and its NSE)
# ─────────────
def export_device(m, path):
    """What the NSE gets through the App Group + shared Keychain access group:
    the device ID, a token, the DPoP key (Secure Enclave key in the shared
    group). Stand-in: a JSON file."""
    json.dump({"account": m.account, "platform": m.platform, "app_id": m.app_id,
        "device_id": m.device_id,
        "token": m.token, "root": os.path.dirname(m.store.app_dir),
        "reply_token": m.token_for_replies.hex(),
        "dpop": m.dpop.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
        ser.NoEncryption()).decode()},
              open(path, "w"))

def restore_device(edge, path, cert_pub, attest):
    d = json.load(open(path))
    m = Messenger(edge, d["account"], d["platform"], d["app_id"], attest,
        d["root"], cert_pub=cert_pub)
    m.dpop = ser.load_pem_private_key(d["dpop"].encode(), None)
    n = m.dpop.public_key().public_numbers()
    m.jwk = {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32, "big")),
        "y": b64u(n.y.to_bytes(32, "big"))}
    m.device_id, m.token, m.token_for_replies = \
        d["device_id"], d["token"], bytes.fromhex(d["reply_token"])
    m._load_identity()
    return m

from murmur_client import b64u
