# nse.py
"""Listing 29.11 — Python: a second PROCESS on the same device database — the
stand-in for the iOS Notification Service Extension (or Android's FCM service)
running at the same moment as the app. Both fetch the same queue; the canonical
pipeline must process each envelope once."""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
BOOK = os.path.dirname(os.path.dirname(HERE))
for d in ("ch18code", "ch19code", "ch20code", "ch21code/attach",
    "ch29code/spec", "ch27code/lab", "ch28code/client"):
    sys.path.insert(0, os.path.join(BOOK, d))
from cryptography.hazmat.primitives import serialization as ser
from murmur_client import Edge
from messenger import Edge29, restore_device

state, lab_dir, mode, start_at, who = sys.argv[1:6]
edge = Edge29(Edge(lab_dir, json.load(open(os.path.join(lab_dir,
    "ready.json")))))
cert_pub = ser.load_pem_public_key(open(os.path.join(lab_dir,
    "sender-cert-key.pub"), "rb").read())
attest = ser.load_pem_private_key(open(os.path.join(lab_dir,
    "lab-attestation-key.pem"), "rb").read(), None)
m = restore_device(edge, state, cert_pub, attest)
# both processes start together
while time.time() < float(start_at): time.sleep(0.001)
got = []
for _ in range(3):
    got += [r[3] for r in m.receive(naive=(mode == "naive"),
        limit=5) if r and r[0] == "message"]
print(json.dumps({"who": who, "decrypted": got}))
