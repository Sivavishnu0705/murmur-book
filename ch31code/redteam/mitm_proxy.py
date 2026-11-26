# mitm_proxy.py
"""Listing 31.5 — Python: an intercepting TLS proxy for the red-team session. It terminates TLS
with a certificate from a ROGUE CA (the "user-installed CA" of Ch 8), forwards to the real
server, and records everything it can read. It shows what pinning stops, and — when the app is
hooked to skip pinning — what is still protected: DPoP-bound tokens and E2EE content."""
import datetime, socket, ssl, threading, os, tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec

def rogue_ca(dirpath):
    k = ec.generate_private_key(ec.SECP256R1()); now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Totally Legit Root CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
          .not_valid_after(now + datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), False)
          .sign(k, hashes.SHA256()))
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.murmur.test")]))
            .issuer_name(name).public_key(lk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.murmur.test")]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(k.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(k, hashes.SHA256()))
    paths = {n: os.path.join(dirpath, n) for n in ("rogue-root.pem", "leaf.pem", "leaf.key")}
    open(paths["rogue-root.pem"], "wb").write(ca.public_bytes(ser.Encoding.PEM))
    open(paths["leaf.pem"], "wb").write(leaf.public_bytes(ser.Encoding.PEM) + ca.public_bytes(ser.Encoding.PEM))
    open(paths["leaf.key"], "wb").write(lk.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    return paths

class InterceptingProxy:
    def __init__(self, upstream_port, dev_root, dirpath):
        self.paths = rogue_ca(dirpath)
        self.upstream_port, self.seen = upstream_port, []
        self.srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.srv_ctx.load_cert_chain(self.paths["leaf.pem"], self.paths["leaf.key"])
        self.up_ctx = ssl.create_default_context(cafile=dev_root)
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            c, _ = self.sock.accept()
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            tls = self.srv_ctx.wrap_socket(c, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.seen.append(("handshake failed", str(e).split("]")[-1].strip()[:60])); return
        try:
            req = b""
            while b"\r\n\r\n" not in req: req += tls.recv(65536)
            head, body = req.split(b"\r\n\r\n", 1)
            n = next((int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")), 0)
            while len(body) < n: body += tls.recv(65536)
            self.seen.append(("request", head.decode(errors="replace"), body))
            up = self.up_ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.upstream_port)), server_hostname="api.murmur.test")
            up.sendall(head.replace(b"\r\n", b"\r\nConnection: close\r\n", 1) + b"\r\n\r\n" + body)
            resp = b""
            while chunk := up.recv(65536): resp += chunk
            tls.sendall(resp); tls.close()
        except Exception as e:
            self.seen.append(("error", str(e)))
