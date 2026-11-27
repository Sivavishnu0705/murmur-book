# Listing 6.4 — Decrypt and verify a captured TLS 1.3 handshake using only the
# key log.
# Usage: python3 dissect_tls13.py capture.c2s capture.s2c keys.log
import hashlib, hmac, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

HS_NAMES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify",
    20: "Finished",
    24: "KeyUpdate"}
SUITES = {0x1301: ("TLS_AES_128_GCM_SHA256", AESGCM, 16, hashlib.sha256),
          0x1302: ("TLS_AES_256_GCM_SHA384", AESGCM, 32, hashlib.sha384),
          0x1303: ("TLS_CHACHA20_POLY1305_SHA256", ChaCha20Poly1305, 32,
          hashlib.sha256)}
GROUPS = {0x001d: "x25519", 0x0017: "secp256r1", 0x11ec: "X25519MLKEM768"}

# ---------- HKDF-Expand-Label (same as Listing 6.1, parameterized by hash)
# ----------
def expand_label(H, secret, label, context, length):
    full = b"tls13 " + label.encode()
    info = struct.pack(">H",
        length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), H).digest()
        out += t
        i += 1
    return out[:length]

# ---------- record and handshake parsing ----------
def records(stream):
    i = 0
    while i + 5 <= len(stream):
        ctype, _ver, length = struct.unpack(">BHH", stream[i:i + 5])
        yield ctype, stream[i:i + 5], stream[i + 5:i + 5 + length]
        i += 5 + length

def handshake_msgs(buf):
    i = 0
    while i + 4 <= len(buf):
        mtype, length = buf[i], int.from_bytes(buf[i + 1:i + 4], "big")
        yield mtype, buf[i:i + 4 + length]
        i += 4 + length

def extensions(body, offset):
    total = int.from_bytes(body[offset:offset + 2], "big"); i = offset + 2
    while i < offset + 2 + total:
        etype, elen = struct.unpack(">HH", body[i:i + 4])
        yield etype, body[i + 4:i + 4 + elen]; i += 4 + elen

class Decryptor:
    """One direction's AEAD state: per-record nonce = iv XOR 64-bit sequence
    number."""
    def __init__(self, suite, secret):
        _, aead, key_len, H = SUITES[suite]
        self.aead = aead(expand_label(H, secret, "key", b"", key_len))
        self.iv = expand_label(H, secret, "iv", b"", 12)
        self.seq = 0
    def open(self, header, ciphertext):
        nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12,
            "big")))
        self.seq += 1
        # header is the AAD
        inner = self.aead.decrypt(nonce, ciphertext, header)
        inner = inner.rstrip(b"\x00")                           # remove padding
        # (real content type, content)
        return inner[-1], inner[:-1]

def main(c2s_path, s2c_path, keylog_path):
    c2s, s2c = open(c2s_path, "rb").read(), open(s2c_path, "rb").read()
    secrets = {}
    for line in open(keylog_path):
        label, _client_random, value = line.split()
        secrets[label] = bytes.fromhex(value)

    # handshake messages, in order
    transcript = []
    # --- plaintext flight: ClientHello, ServerHello ---
    ch = next(r for r in records(c2s) if r[0] == 22)[2]
    transcript.append(ch)
    s2c_recs = list(records(s2c))
    sh = next(r for r in s2c_recs if r[0] == 22)[2]
    transcript.append(sh)
    suite = int.from_bytes(sh[4 + 2 + 32 + 1 + sh[4 + 2 + 32]:][:2], "big")
    name, _, _, H = SUITES[suite]

    print("── plaintext ──────────────────────────────────────────────")
    sid_len = ch[4 + 34]; p = 4 + 35 + sid_len
    cs_len = int.from_bytes(ch[p:p + 2], "big"); p += 2 + cs_len
    p += 1 + ch[p]                                     # compression methods
    for etype, data in extensions(ch, p):
        if etype == 51:                                # key_share
            j, shares = 2, []
            while j < len(data):
                g, ln = struct.unpack(">HH", data[j:j + 4])
                shares.append(f"{GROUPS.get(g, hex(g))} ({ln} B)")
                j += 4 + ln
            print(f"ClientHello   {len(ch)} B   key_share: {', '.join(shares)}")
        if etype == 0:
            print(f"              SNI: {data[5:].decode()}")
    sp = 4 + 2 + 32 + 1 + sh[4 + 2 + 32] + 3
    for etype, data in extensions(sh, sp):
        if etype == 51:
            g, ln = struct.unpack(">HH", data[:4])
            print(
                f"ServerHello   {len(sh)} B   cipher: {name}   key_share: "
                f"{GROUPS.get(g, hex(g))} ({ln} B)")
        if etype == 43:
            print(
                f"              supported_versions: "
                f"0x{int.from_bytes(data, 'big'):04x} (TLS 1.3)")

    # --- encrypted server flight ---
    print("── encrypted with server handshake traffic keys ──────────")
    dec = Decryptor(suite, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"])
    server_hs, app_recs = b"", []
    for ctype, header, body in s2c_recs:
        if ctype == 20:
            # middlebox-compat ChangeCipherSpec: ignore
            continue
        if ctype == 23 and dec is not None:
            real_type, content = dec.open(header, body)
            if real_type == 22:
                server_hs += content
                if any(m == 20 for m, _ in handshake_msgs(server_hs)):
                    # Finished seen: handshake keys done
                    dec = None
            continue
        if ctype == 23:
            app_recs.append((header, body))

    leaf = None
    for mtype, msg in handshake_msgs(server_hs):
        # transcript BEFORE this message
        th = H(b"".join(transcript)).digest()
        if mtype == 11:
            cl = int.from_bytes(msg[5 + msg[4]:8 + msg[4]], "big")
            q = 8 + msg[4]
            n = 0
            while q < 8 + msg[4] + cl:
                ln = int.from_bytes(msg[q:q + 3], "big")
                cert = x509.load_der_x509_certificate(msg[q + 3:q + 3 + ln])
                leaf = leaf or cert
                print(
                    f"Certificate         [{n}] "
                    f"{cert.subject.rfc4514_string()}")
                q += 3 + ln
                q += 2 + int.from_bytes(msg[q:q + 2], "big")
                n += 1
        elif mtype == 15:
            scheme = int.from_bytes(msg[4:6], "big"); sig = msg[8:]
            content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" \
                + th
            leaf.public_key().verify(sig, content, ec.ECDSA(hashes.SHA256()))
            print(
                f"CertificateVerify   scheme 0x{scheme:04x}  signature over "
                f"transcript: VALID")
        elif mtype == 20:
            fk = expand_label(H, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"],
                "finished", b"", H().digest_size)
            ok = hmac.compare_digest(msg[4:], hmac.new(fk, th, H).digest())
            print(
                f"Finished (server)   HMAC over transcript: "
                f"{'VALID' if ok else 'INVALID'}")
        else:
            print(f"{HS_NAMES.get(mtype, mtype):<19} {len(msg)} B")
        transcript.append(msg)

    # --- encrypted client Finished ---
    print("── encrypted with client handshake traffic keys ──────────")
    cdec = Decryptor(suite, secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"])
    c_app = []
    for ctype, header, body in list(records(c2s))[1:]:
        if ctype == 20:
            continue
        if cdec is not None:
            real_type, content = cdec.open(header, body)
            th = H(b"".join(transcript)).digest()
            fk = expand_label(H, secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"],
                "finished", b"", H().digest_size)
            ok = hmac.compare_digest(content[4:], hmac.new(fk, th, H).digest())
            print(
                f"Finished (client)   HMAC over transcript: "
                f"{'VALID' if ok else 'INVALID'}")
            cdec = None
        else:
            c_app.append((header, body))

    # --- application data ---
    print("── application traffic keys ──────────────────────────────")
    cap = Decryptor(suite, secrets["CLIENT_TRAFFIC_SECRET_0"])
    for header, body in c_app:
        t, content = cap.open(header, body)
        if t == 23:
            print("client → server:", content.split(b"\r\n")[0].decode())
    sap = Decryptor(suite, secrets["SERVER_TRAFFIC_SECRET_0"])
    for header, body in app_recs:
        t, content = sap.open(header, body)
        if t == 22:
            for m, msg in handshake_msgs(content):
                print(
                    f"server → client: {HS_NAMES.get(m, m)} ({len(msg)} B, "
                    f"post-handshake)")
        elif t == 23:
            print("server → client:",
                content.split(b"\r\n")[-1].decode().strip())

if __name__ == "__main__":
    main(*sys.argv[1:4])
