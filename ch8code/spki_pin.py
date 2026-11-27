# Listing 8.4 (Python) — compute the SPKI SHA-256 pin of every certificate in a
# PEM file.
# Usage: python3 spki_pin.py chain.pem
import base64, hashlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def spki_pin(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat
                                          .SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()

if __name__ == "__main__":
    for cert in x509.load_pem_x509_certificates(open(sys.argv[1], "rb").read()):
        print(f"{spki_pin(cert)}  {cert.subject.rfc4514_string()}")
