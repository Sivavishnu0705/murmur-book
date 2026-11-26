# stored_device.py
"""Listing 28.11 — Python: the client key lifecycle of Chapter 28 — generation, storage in the
SQLCipher model, upload, prekey maintenance (the logic of the WorkManager / BGTaskScheduler
job), and retries with idempotency keys. Builds on the Chapter 27 client (Listing 27.13)."""
import os, time, uuid
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import xeddsa, x3dh
from murmur_client import Device, b64, unb64
from device_store import DeviceStore

DAY = 86400
OPK_TARGET, OPK_LOW = 100, 20            # Ch 18: 100 one-time prekeys, replenish below 20
PQ_TARGET, PQ_LOW = 40, 15               # one-time ML-KEM-1024 prekeys (1,568 B each on the server)
SPK_ROTATE, SPK_RETAIN = 7 * DAY, 30 * DAY

class StoredDevice(Device):
    def __init__(self, edge, account, platform, app_id, attest_key, root, push_token=""):
        super().__init__(edge, account, platform, app_id, attest_key, push_token)
        self.store = DeviceStore(os.path.join(root, "app"), os.path.join(root, "hardware"))
        self.lost_responses = 0

    # ── 28.3: identity key and AIK, generated in software, wrapped by the hardware key ──
    def create_identity(self):
        ik = x3dh.KeyPair()
        self.store.put_identity("device_identity", ik.pub, ik.priv)
        aik = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization as ser
        self.store.put_identity("account_identity", aik.public_key().public_bytes_raw(),
                                aik.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()))
        self._load_identity()

    def _load_identity(self):
        pub, priv = self.store.identity("device_identity")
        self.ik = x3dh.KeyPair(priv)
        assert self.ik.pub == pub

    def _sign(self, typ, pub):
        return xeddsa.sign(self.ik.priv, bytes([typ]) + pub)

    def _new_signed(self, now):
        spk = x3dh.KeyPair(); sid = self.store.next_id("spk")
        pq = mlkem.MLKEM1024PrivateKey.generate(); pid = self.store.next_id("pqlr")
        pq_pub = pq.public_key().public_bytes_raw()
        self.store.add_prekeys("spk", [(sid, spk.pub, spk.priv)], now)
        self.store.add_prekeys("pqlr", [(pid, pq_pub, pq.private_bytes_raw())], now)
        return ({"id": sid, "pub": b64(spk.pub), "sig": b64(self._sign(0x05, spk.pub))},
                {"id": pid, "pub": b64(pq_pub), "sig": b64(self._sign(0x08, pq_pub))})

    def _new_one_time(self, n_ec, n_pq, now):
        ec, pq = [], []
        for _ in range(n_ec):
            k = x3dh.KeyPair(); i = self.store.next_id("opk"); ec.append((i, k.pub, k.priv))
        for _ in range(n_pq):
            k = mlkem.MLKEM1024PrivateKey.generate(); i = self.store.next_id("pqopk")  # stored as its 64-byte seed
            pq.append((i, k.public_key().public_bytes_raw(), k.private_bytes_raw()))
        # Private halves are committed BEFORE the upload: a key the server hands out must exist here.
        self.store.add_prekeys("opk", ec, now); self.store.add_prekeys("pqopk", pq, now)
        return ([{"id": i, "pub": b64(p)} for i, p, _ in ec],
                [{"id": i, "pub": b64(p), "sig": b64(self._sign(0x08, p))} for i, p, _ in pq])

    def register_keys(self, now):
        st1, _ = self.call("POST", "/v1/keys/identity", {"identity_key": b64(self.ik.pub)})
        spk, pqlr = self._new_signed(now)
        ec, pq = self._new_one_time(OPK_TARGET, PQ_TARGET, now)
        st2, _ = self.call("PUT", "/v1/keys/prekeys", {"signed_prekey": spk, "pq_last_resort": pqlr, "one_time": ec, "pq_one_time": pq})
        return st1, st2

    # ── 28.5: the background job. Idempotent: safe to run at any time, any number of times. ──
    def maintain(self, now):
        did = []
        st, c = self.call("GET", "/v1/keys/count")
        up = {}
        if c["one_time"] < OPK_LOW or c["pq_one_time"] < PQ_LOW:
            ec, pq = self._new_one_time(OPK_TARGET - c["one_time"] if c["one_time"] < OPK_LOW else 0,
                                        PQ_TARGET - c["pq_one_time"] if c["pq_one_time"] < PQ_LOW else 0, now)
            up.update(one_time=ec, pq_one_time=pq); did.append(f"+{len(ec)} OPK +{len(pq)} PQ")
        sid, created = self.store.current_signed("spk")
        if now - created >= SPK_ROTATE:
            spk, pqlr = self._new_signed(now)
            up.update(signed_prekey=spk, pq_last_resort=pqlr); did.append(f"SPK {sid}→{spk['id']}")
        if up:
            st, _ = self.call("PUT", "/v1/keys/prekeys", up)
            if st != 204: return [f"upload failed {st}"]
            if "signed_prekey" in up:   # old SPK stays usable for in-flight PreKeyMessages for 30 days
                self.store.supersede("spk", up["signed_prekey"]["id"], now)
                self.store.supersede("pqlr", up["pq_last_resort"]["id"], now)
        # One-time keys the server has HANDED OUT but no message has used yet: the server serves the
        # lowest ID first, so every local ID ≤ (highest uploaded − count on server) is gone from the
        # server. Keep each for 30 days (a PreKeyMessage may still be in flight), then delete it.
        for kind, server_count in (("opk", c["one_time"]), ("pqopk", c["pq_one_time"])):
            self.store.mark_handed_out(kind, self.store.next_id_peek(kind) - 1 - server_count, now)
        purged = sum(self.store.purge_superseded(k, now - SPK_RETAIN) for k in ("spk", "pqlr", "opk", "pqopk"))
        if purged: did.append(f"deleted {purged} expired private key(s)")
        return did

    # ── 28.6: every state-changing call carries an Idempotency-Key, reused on retry ──
    def call(self, method, path, body=None, proof=None, scheme="DPoP", token=None, idem=None, lose_first_response=False):
        if method in ("POST", "PUT") and idem is None:
            idem = str(uuid.uuid4())
        for attempt in range(3):
            hdr = {"Authorization": f"{scheme} {token or self.token}", "Content-Type": "application/json"}
            hdr["DPoP"] = proof or self.proof(method, "https://api.murmur.test" + path, token or self.token)  # new jti per attempt
            if idem: hdr["Idempotency-Key"] = idem
            st, js, h = self.edge.request("api", method, path, body, hdr)
            if lose_first_response and attempt == 0:
                self.lost_responses += 1; continue      # the response never reached the app: retry
            if st in (502, 503, 504) or (st == 429 and js.get("retryable")):
                time.sleep(0.2 * 2 ** attempt); continue
            if h.get("Idempotent-Replayed"): js = dict(js or {}, replayed=True)
            if st == 401 and "WWW-Authenticate" in h: js["www_authenticate"] = h["WWW-Authenticate"]
            return st, js
        return st, js

    # ── receiving the first message: keys come out of the encrypted store, and one-time keys
    #    are deleted only AFTER decryption succeeds (Ch 19 §19.9: decrypt and persist together) ──
    def decrypt(self, env_bytes, sender_device):
        import murmur_pb2 as pb
        env = pb.Envelope.FromString(env_bytes)
        used = []
        if env.type == pb.PREKEY_MESSAGE:
            m = pb.PreKeyMessage.FromString(env.content)
            self.spk = x3dh.KeyPair(self.store.get("spk", m.signed_prekey_id))
            seed = self.store.get("pqopk", m.pq_prekey_id)
            if seed: used.append(("pqopk", m.pq_prekey_id))
            else: seed = self.store.get("pqlr", m.pq_prekey_id)          # last resort: not deleted
            self.pq_opks = {m.pq_prekey_id: mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)}
            if m.HasField("one_time_prekey_id"):
                self.opks = {m.one_time_prekey_id: x3dh.KeyPair(self.store.get("opk", m.one_time_prekey_id))}
                used.append(("opk", m.one_time_prekey_id))
        pt = super().decrypt(env_bytes, sender_device)
        for kind, i in used:
            self.store.take_one_time(kind, i)
        return pt
