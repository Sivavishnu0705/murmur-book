# Listing 6.1 — The TLS 1.3 key schedule (SHA-256 suites), checked against RFC 8448 §3.
# Save as tls13_key_schedule.py: the lab (Step 5) imports it.
import hashlib
import hmac

H = hashlib.sha256
HASH_LEN = 32

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(HASH_LEN), ikm, H).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), H).digest()
        out, i = out + t, i + 1
    return out[:length]

def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """RFC 8446 §7.1: struct HkdfLabel { uint16 length; opaque label<7..255> = "tls13 " + Label;
    opaque context<0..255>; }"""
    full = b"tls13 " + label.encode()
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length)

def derive_secret(secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)

def traffic_keys(traffic_secret: bytes, key_len: int = 16) -> tuple[bytes, bytes]:
    return (hkdf_expand_label(traffic_secret, "key", b"", key_len),
            hkdf_expand_label(traffic_secret, "iv", b"", 12))

def schedule(ecdhe: bytes, hash_ch_sh: bytes, hash_ch_sf: bytes, psk: bytes = b"") -> dict:
    empty = H(b"").digest()
    early = hkdf_extract(b"", psk or bytes(HASH_LEN))          # no PSK → zeros
    hs_salt = derive_secret(early, "derived", empty)
    handshake = hkdf_extract(hs_salt, ecdhe)
    main_salt = derive_secret(handshake, "derived", empty)
    main = hkdf_extract(main_salt, bytes(HASH_LEN))            # "master secret" in RFC 8446
    return {
        "early_secret": early,
        "derived_for_handshake": hs_salt,
        "handshake_secret": handshake,
        "c_hs_traffic": derive_secret(handshake, "c hs traffic", hash_ch_sh),
        "s_hs_traffic": derive_secret(handshake, "s hs traffic", hash_ch_sh),
        "main_secret": main,
        "c_ap_traffic": derive_secret(main, "c ap traffic", hash_ch_sf),
        "s_ap_traffic": derive_secret(main, "s ap traffic", hash_ch_sf),
        "exporter_secret": derive_secret(main, "exp master", hash_ch_sf),
    }

if __name__ == "__main__":
    x = bytes.fromhex
    # Inputs from RFC 8448 §3 (Simple 1-RTT Handshake, TLS_AES_128_GCM_SHA256, X25519)
    ecdhe      = x("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    hash_ch_sh = x("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
    hash_ch_sf = x("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
    expected = {
        "derived_for_handshake": "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
        "handshake_secret": "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
        "c_hs_traffic": "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
        "s_hs_traffic": "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
        "main_secret": "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
        "c_ap_traffic": "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
        "s_ap_traffic": "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
    }
    got = schedule(ecdhe, hash_ch_sh, hash_ch_sf)
    for name, want in expected.items():
        status = "OK " if got[name].hex() == want else "BAD"
        print(f"{status} {name:22} {got[name].hex()}")
    key, iv = traffic_keys(got["s_hs_traffic"])
    assert key.hex() == "3fce516009c21727d0f2e4e86ee403bc"
    assert iv.hex() == "5d313eb2671276ee13000b30"
    print(f"OK  server hs key        {key.hex()}\nOK  server hs iv         {iv.hex()}")
    assert all(got[k].hex() == v for k, v in expected.items())
    print("All values match RFC 8448 §3.")
