# attach_client.py
"""Listing 29.7 — Python: attachment send and receive (model of Listings 29.5
and 29.6) — STREAM encryption with a fixed 64 KiB buffer (Ch 21 §21.5),
resumable upload with Content-Range, and a download that verifies the digest and
every chunk before the plaintext is released (renamed into place). Memory stays
flat whatever the file size."""
import hashlib, os
# Listing 21.4: stream_encrypt / stream_decrypt
import attachments
import murmur_pb2 as pb
from murmur_client import b64

CHUNK = 256 * 1024                                     # upload request size

def encrypt_file(src_path, dst_path):
    key = os.urandom(32)
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        # reads and writes 64 KiB at a time
        attachments.stream_encrypt(src, dst, key)
    h, size = hashlib.sha256(), 0
    with open(dst_path, "rb") as f:
        while b := f.read(attachments.BUF): h.update(b); size += len(b)
    return key, h.digest(), size

def upload(dev, blob_path, size, drop_after=None):
    """Resumable: on a dropped connection, HEAD tells us the offset and we
    continue from there."""
    st, a = dev.call("POST", "/v1/attachments", {"size": size})
    path = a["upload_url"].split("api.murmur.test")[1]
    offset, sent_requests, resumed_at = 0, 0, None
    with open(blob_path, "rb") as f:
        while offset < size:
            if drop_after is not None and sent_requests == drop_after:
                # the network drops once…
                drop_after = None
                # …the client asks where to resume
                st, _, h = dev.edge.request("api", "HEAD", path)
                offset = int(h["Upload-Offset"]); resumed_at = offset
            f.seek(offset); chunk = f.read(CHUNK)
            st, js, h = dev.edge.request("api", "PUT", path, chunk,
                {
                "Content-Range": f"bytes "
                f"{offset}-{offset + len(chunk) - 1}/{size}"})
            if st not in (201, 202): raise IOError(f"upload failed: {st} {js}")
            offset += len(chunk); sent_requests += 1
    return a["cdn_id"], resumed_at, sent_requests

def pointer(cdn_id, key, digest, size, content_type):
    return pb.AttachmentPointer(cdn_id=cdn_id, key=key,
        ciphertext_sha256=digest, size=size, content_type=content_type)

def _stream_get(edge, path, out_path):
    """GET with a fixed buffer: ciphertext goes straight to a temp file, hashed
    on the way."""
    import socket, http.client
    sock = socket.create_connection(("127.0.0.1", edge.ports["api"]))
    # same pinned context
    tls = edge.ctx.wrap_socket(sock, server_hostname="api.murmur.test")
    conn = http.client.HTTPConnection("api.murmur.test"); conn.sock = tls
    conn.request("GET", path); r = conn.getresponse()
    h = hashlib.sha256()
    with open(out_path, "wb") as out:
        while b := r.read(attachments.BUF):
            h.update(b); out.write(b)
    conn.close()
    return r.status, h.digest()

def download(dev, ptr, dst_path, max_size=None, tamper=False):
    """Stream to temp files; release (rename) the plaintext only if the digest
    AND every chunk verify. Memory use is a few 64 KiB buffers, whatever the
    attachment size."""
    if max_size is not None and ptr.size > max_size:
        return ("too large for this context: placeholder shown, "
                "the app fetches it later")
    enc, tmp = dst_path + ".enc", dst_path + ".partial"
    st, digest = _stream_get(dev.edge.inner if hasattr(dev.edge,
        "inner") else dev.edge, f"/cdn/{ptr.cdn_id}", enc)
    try:
        # a byte changed in transit or on the CDN
        if tamper:
            with open(enc, "r+b") as f:
                f.seek(ptr.size // 2)
                b = f.read(1)
                f.seek(ptr.size // 2)
                f.write(bytes([b[0] ^ 1]))
            digest = hashlib.sha256(open(enc, "rb").read()).digest()
        if (
            st != 200 or
            digest != ptr.ciphertext_sha256) and tamper != "skip-digest-check":
            return "digest mismatch: discarded, nothing released"
        with open(enc, "rb") as src, open(tmp, "wb") as out:
            # each chunk released only after its tag verifies
            for pt in attachments.stream_decrypt(src, ptr.key):
                out.write(pt)
        # atomic release
        os.replace(tmp, dst_path)
        return "released"
    except ValueError as e:
        if os.path.exists(tmp): os.remove(tmp)
        return f"discarded before release: {e}"
    finally:
        if os.path.exists(enc): os.remove(enc)
