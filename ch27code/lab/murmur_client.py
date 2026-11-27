# murmur_client.py
"""Listing 27.13 — Python: scripted Murmur client for the server integration
tests. Real protocol code from earlier chapters: XEdDSA and X3DH (Ch 18), PQXDH
with ML-KEM-1024 (Ch 18), the Double Ratchet (Ch 19), STREAM attachments (Ch
21), and the Ch 26 protobuf schema. Transport: TLS 1.3 to *.murmur.test with the
Edge CA SPKI pinned, DPoP on every call."""
import base64, hashlib, http.client, json, os, socket, ssl, struct, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import xeddsa, x3dh, ratchet, murmur_pb2 as pb

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode

class Edge:
    """TLS 1.3 to 127.0.0.1:<port> with SNI <name>.murmur.test; the Edge CA's
    SPKI must appear in the verified chain (pinning on top of validation, Ch 8).
    """
    def __init__(self, lab_dir, ready):
        self.ctx = ssl.create_default_context(cafile=os.path.join(lab_dir,
            "root.pem"))
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ports, self.pin = ready["ports"], ready["edge_pin"]
    def request(self, host, method, path, body=None, headers=None):
        sock = socket.create_connection(("127.0.0.1", self.ports[host]))
        tls = self.ctx.wrap_socket(sock, server_hostname=f"{host}.murmur.test")
        pins = {b64(hashlib.sha256(x509.load_der_x509_certificate(
            c).public_key().public_bytes(
            ser.Encoding.DER,
            ser.PublicFormat.SubjectPublicKeyInfo)).digest()) for
            c in tls.get_verified_chain()[1:]}
        if self.pin not in pins:
            tls.close(); raise ssl.SSLError("pin mismatch")
        conn = http.client.HTTPConnection(f"{host}.murmur.test")
        conn.sock = tls
        data = body if isinstance(body,
            bytes) else (json.dumps(
            body).encode() if body is not None else None)
        conn.request(method, path, body=data, headers=headers or {})
        r = conn.getresponse(); raw = r.read(); conn.close()
        try: js = json.loads(raw) if raw else {}
        except ValueError: js = {"raw": raw}
        return r.status, js, r.headers

class Device:
    def __init__(self, edge, account, platform, app_id, attest_key,
        push_token=""):
        self.edge, self.account, self.platform, self.app_id = \
            edge, account, platform, app_id
        self.attest_key, self.push_token = attest_key, push_token
        # Keystore/Secure Enclave stand-in
        self.dpop = ec.generate_private_key(ec.SECP256R1())
        n = self.dpop.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32,
            "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        # device identity key (X25519)
        self.ik = x3dh.KeyPair()
        self.spk = x3dh.KeyPair(); self.spk_id = 1
        self.pq_last = mlkem.MLKEM1024PrivateKey.generate()
        self.opks, self.pq_opks, self.sessions, self.token, self.device_id = \
            {}, {}, {}, None, None

    def _sign_ecdsa(self, key, msg):
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        # JWS / Murmur: raw r‖s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def proof(self, method, url, at=None):
        h = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}
        c = {"jti": b64u(os.urandom(16)), "htm": method, "htu": url,
            "iat": int(time.time())}
        if at: c["ath"] = b64u(hashlib.sha256(at.encode()).digest())
        si = b64u(json.dumps(h).encode()) + "." + b64u(json.dumps(c).encode())
        return si + "." + b64u(self._sign_ecdsa(self.dpop, si.encode()))

    def login(self, phr=True, app_id=None, reuse_nonce=None):
        """Enroll (first call) or get a fresh token for the enrolled device
        (later calls)."""
        body = {"account": self.account, "platform": self.platform, "phr": phr,
            "push_token": self.push_token}
        if self.device_id is None:
            nonce = reuse_nonce or unb64(self.edge.request("auth", "POST",
                "/v1/enroll/challenge")[1]["nonce"])
            spki = self.dpop.public_key().public_bytes(ser.Encoding.DER,
                ser.PublicFormat.SubjectPublicKeyInfo)
            app = app_id or self.app_id
            att = self._sign_ecdsa(self.attest_key,
                b"lab-attestation\x00" + app.encode() + b"\x00" + nonce +
                b"\x00" + spki)
            body.update(nonce=b64(nonce), pop=b64(self._sign_ecdsa(self.dpop,
                b"murmur/v1/enroll-pop\x00" + nonce + self.account.encode())),
                attestation=b64(json.dumps({"app_id": app,
                "sig": b64(att)}).encode()))
            self.last_nonce = nonce
        st, js, _ = self.edge.request("auth", "POST", "/v1/token", body,
                                      {"DPoP": self.proof("POST",
                                      "https://auth.murmur.test/v1/token"),
                                      "Content-Type": "application/json"})
        if st == 200:
            self.token, self.device_id = js["access_token"], js["device_id"]
        return st, js

    def call(self, method, path, body=None, proof=None, scheme="DPoP",
        token=None):
        tok = token or self.token
        hdr = {"Authorization": f"{scheme} {tok}",
            "Content-Type": "application/json"}
        hdr["DPoP"] = proof or self.proof(method,
            "https://api.murmur.test" + path, tok)
        st, js, h = self.edge.request("api", method, path, body, hdr)
        if st == 401 and "WWW-Authenticate" in h:
            js["www_authenticate"] = h["WWW-Authenticate"]
        return st, js

    # ── keys ──
    def upload_keys(self, n_opk=5, n_pq=2):
        st1, _ = self.call("POST", "/v1/keys/identity",
            {"identity_key": b64(self.ik.pub)})
        self.opks = {i: x3dh.KeyPair() for i in range(1, n_opk + 1)}
        self.pq_opks = {
            100 + i: mlkem.MLKEM1024PrivateKey.generate() for i in range(1,
            n_pq + 1)}
        signed = lambda typ, pub: b64(xeddsa.sign(self.ik.priv,
            bytes([typ]) + pub))
        pqpub = lambda k: k.public_key().public_bytes_raw()
        up = {"signed_prekey": {"id": self.spk_id, "pub": b64(self.spk.pub),
            "sig": signed(0x05, self.spk.pub)},
            "pq_last_resort": {"id": 99, "pub": b64(pqpub(self.pq_last)),
            "sig": signed(0x08, pqpub(self.pq_last))},
            "one_time": [{"id": i, "pub": b64(k.pub)} for i,
            k in self.opks.items()],
            "pq_one_time": [{"id": i, "pub": b64(pqpub(k)), "sig": signed(0x08,
            pqpub(k))} for i, k in self.pq_opks.items()]}
        st2, _ = self.call("PUT", "/v1/keys/prekeys", up)
        return st1, st2

    # ── PQXDH initiator (Ch 18 §18.7) + first Double Ratchet message (Ch 19) ──
    def start_session(self, peer_device, bundle, plaintext):
        ik, spk = unb64(bundle["identity_key"]), unb64(
            bundle["signed_prekey"]["pub"])
        pq = bundle["pq_prekey"]; pqpk = unb64(pq["pub"])
        if not (xeddsa.verify(ik, b"\x05" + spk,
            unb64(bundle["signed_prekey"]["sig"])) and
            xeddsa.verify(ik, b"\x08" + pqpk, unb64(pq["sig"]))):
            # the server cannot swap keys
            raise ValueError("bundle signature invalid: abort")
        ek = x3dh.KeyPair()
        ss, kem_ct = mlkem.MLKEM1024PublicKey.from_public_bytes(
            pqpk).encapsulate()
        km = x3dh.DH(self.ik, spk) + x3dh.DH(ek, ik) + x3dh.DH(ek, spk)
        opk = bundle.get("one_time_prekey")
        if opk: km += x3dh.DH(ek, unb64(opk["pub"]))
        sk = HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
            info=b"Murmur_CURVE25519_SHA-256_ML-KEM-1024").derive(
            x3dh.F + km + ss)
        ad = x3dh.encode(self.ik.pub) + x3dh.encode(ik)
        r = ratchet.Ratchet.init_alice(sk, spk)
        self.sessions[peer_device] = (r, ad)
        hdr, ct = r.encrypt(pad(plaintext), ad)
        m = pb.PreKeyMessage(suite=0x0002, identity_key=self.ik.pub,
            ephemeral_key=ek.pub,
            signed_prekey_id=bundle["signed_prekey"]["id"],
            pq_prekey_id=pq["id"], kem_ciphertext=kem_ct,
            message=pb.RatchetMessage(header=hdr, ciphertext=ct))
        if opk: m.one_time_prekey_id = opk["id"]
        return pb.Envelope(version=1, type=pb.PREKEY_MESSAGE,
            recipient_device=peer_device,
            content=m.SerializeToString()).SerializeToString()

    def encrypt(self, peer_device, plaintext):
        r, ad = self.sessions[peer_device]
        hdr, ct = r.encrypt(pad(plaintext), ad)
        return pb.Envelope(version=1, type=pb.RATCHET_MESSAGE,
            recipient_device=peer_device,
            content=pb.RatchetMessage(header=hdr,
            ciphertext=ct).SerializeToString()).SerializeToString()

    def decrypt(self, env_bytes, sender_device):
        env = pb.Envelope.FromString(env_bytes)
        if env.version != 1: raise ValueError("UNSUPPORTED_VERSION")
        if env.type == pb.PREKEY_MESSAGE:
            m = pb.PreKeyMessage.FromString(env.content)
            # rule V1
            if m.suite != 0x0002: raise ValueError("UNSUPPORTED_SUITE")
            pq_priv = self.pq_opks.pop(m.pq_prekey_id,
                None) or (self.pq_last if m.pq_prekey_id == 99 else None)
            ss = pq_priv.decapsulate(m.kem_ciphertext)
            km = x3dh.DH(self.spk, m.identity_key) + x3dh.DH(self.ik,
                m.ephemeral_key) + x3dh.DH(self.spk, m.ephemeral_key)
            if m.HasField("one_time_prekey_id"):
                # delete after use
                km += x3dh.DH(self.opks.pop(m.one_time_prekey_id),
                    m.ephemeral_key)
            sk = HKDF(hashes.SHA256(), 32, salt=b"\x00" * 32,
                info=b"Murmur_CURVE25519_SHA-256_ML-KEM-1024").derive(
                x3dh.F + km + ss)
            ad = x3dh.encode(m.identity_key) + x3dh.encode(self.ik.pub)
            r = ratchet.Ratchet.init_bob(sk, ratchet.DHPair(self.spk.priv))
            self.sessions[sender_device] = (r, ad)
            rm = m.message
        else:
            rm = pb.RatchetMessage.FromString(env.content)
        r, ad = self.sessions[sender_device]
        return unpad(r.decrypt(rm.header, rm.ciphertext, ad))

# Ch 21 §21.6: 0x80 then zeros
def pad(b, bucket=160):
    n = -(-(len(b) + 1) // bucket) * bucket
    return b + b"\x80" + b"\x00" * (n - len(b) - 1)

def unpad(b):
    s = b.rstrip(b"\x00")
    # uniform error
    if not s.endswith(b"\x80"): raise ValueError("DECRYPTION_FAILED")
    return s[:-1]

# Ch 20 Listing 20.1, byte for byte
def encode_device_list(account, version, devices):
    put = lambda s: struct.pack(">I", len(s)) + s
    out = put(b"murmur device list v1") + put(account.encode()) + struct.pack(
        ">Q", version) + struct.pack(">I", len(devices))
    for d in sorted(devices, key=lambda d: d["id"]):
        out += put(d["id"].encode()) + d["ik"] + put(
            d["name"].encode()) + struct.pack(">q", d["added"])
    return out
