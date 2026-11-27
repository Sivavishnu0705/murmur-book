# Listing 4.3 — Parse a certificate and print the fields that carry its real
# meaning.
# Usage: python3 inspect_cert.py cert.pem
import sys
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization

EKU_NAMES = {ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
             ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth"}

def ext(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None

def main(path: str) -> None:
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    print("subject    :", cert.subject.rfc4514_string())
    print("issuer     :", cert.issuer.rfc4514_string())
    print("validity   :", cert.not_valid_before_utc, "→",
        cert.not_valid_after_utc,
        f"({(cert.not_valid_after_utc - cert.not_valid_before_utc).days} days)")
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat
                                          .SubjectPublicKeyInfo)
    h = hashes.Hash(hashes.SHA256()); h.update(spki)
    print("SPKI sha256:", h.finalize().hex(),
        " (the value you would pin, Chapter 8)")

    bc = ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    print("basic cons :", "MISSING" if bc is None else
          f"CA={bc.value.ca} pathlen={bc.value.path_length} "
          f"critical={bc.critical}")

    san = ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san:
        print("SAN DNS    :", san.value.get_values_for_type(x509.DNSName))
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            print("SAN URI    :", uris)
    else:
        print("SAN        : MISSING — modern clients will reject this for TLS")

    eku = ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    print("EKU        :", "none (any purpose)" if eku is None else
          [EKU_NAMES.get(o, o.dotted_string) for o in eku.value])

    scts = ext(cert, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    if scts:
        for s in scts.value:
            print(
                f"SCT        : log {s.log_id.hex()[:16]}…  at "
                f"{s.timestamp:%Y-%m-%d %H:%M:%S} UTC")
    else:
        print(
            "SCT        : none embedded (fine for a private CA; required for "
            "public trust)")

if __name__ == "__main__":
    main(sys.argv[1])
