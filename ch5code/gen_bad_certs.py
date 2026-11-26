# Listing 5.5 — Generate a suite of deliberately broken certificate chains.
# Usage: python3 gen_bad_certs.py ./cases
# Every case is served for the same name, api.murmur.test, so only ONE thing differs.
import datetime as dt
import pathlib
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HOST = "api.murmur.test"
NOW = dt.datetime.now(dt.timezone.utc)
DAY = dt.timedelta(days=1)

def key():
    return ec.generate_private_key(ec.SECP256R1())

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def build(subject_cn, pub, issuer_cn, issuer_key, *, ca, pathlen=None,
          sans=None, eku=None, not_before=None, not_after=None):
    b = (x509.CertificateBuilder()
         .subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(not_before or NOW - DAY)
         .not_valid_after(not_after or NOW + 30 * DAY)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
         # RFC 5280 key identifiers: strict verifiers (e.g. Python 3.13+) require the AKI.
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             issuer_key.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False,
                                          True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False,
                                          False, False, False, False), critical=True)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                            critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(issuer_key, hashes.SHA256())

def pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)

def keypem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())

def main(out):
    out = pathlib.Path(out); out.mkdir(parents=True, exist_ok=True)
    root_k = key()
    root = build("Test Root", root_k.public_key(), "Test Root", root_k, ca=True, pathlen=1,
                 not_after=NOW + 3650 * DAY)
    inter_k = key()
    inter = build("Test Intermediate", inter_k.public_key(), "Test Root", root_k,
                  ca=True, pathlen=0)
    (out / "root.pem").write_bytes(pem(root))
    server = [ExtendedKeyUsageOID.SERVER_AUTH]

    def leaf(**kw):
        k = key()
        kw.setdefault("sans", [HOST]); kw.setdefault("eku", server)
        return k, build(HOST, k.public_key(), "Test Intermediate", inter_k, ca=False, **kw)

    cases = {}
    k, c = leaf();                                   cases["good"] = (k, [c, inter])
    k, c = leaf(not_after=NOW - DAY,
                not_before=NOW - 31 * DAY);          cases["expired"] = (k, [c, inter])
    k, c = leaf(not_before=NOW + 10 * DAY,
                not_after=NOW + 40 * DAY);           cases["not-yet-valid"] = (k, [c, inter])
    k, c = leaf(sans=["evil.murmur.test"]);          cases["wrong-host"] = (k, [c, inter])
    k, c = leaf(eku=[ExtendedKeyUsageOID.CLIENT_AUTH]); cases["wrong-eku"] = (k, [c, inter])
    k, c = leaf();                                   cases["missing-intermediate"] = (k, [c])
    k, c = leaf(sans=["*.test"]);                    cases["wildcard-multi-label"] = (k, [c, inter])
    k, c = leaf(not_after=NOW + 400 * DAY);          cases["long-lived"] = (k, [c, inter])

    # A "CA" that is really a leaf: CA:FALSE intermediate signing a server cert.
    bad_k = key()
    bad_inter = build("Not A CA", bad_k.public_key(), "Test Root", root_k, ca=False)
    lk = key()
    lc = build(HOST, lk.public_key(), "Not A CA", bad_k, ca=False, sans=[HOST], eku=server)
    cases["ca-false-intermediate"] = (lk, [lc, bad_inter])

    # Self-signed leaf: valid name, valid dates, no path to the trusted root.
    sk = key()
    sc = build(HOST, sk.public_key(), HOST, sk, ca=False, sans=[HOST], eku=server)
    cases["self-signed"] = (sk, [sc])

    for case, (k, chain) in cases.items():
        (out / f"{case}.chain.pem").write_bytes(pem(*chain))
        (out / f"{case}.key.pem").write_bytes(keypem(k))
    print("cases:", ", ".join(cases))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "./cases")
