// AttachmentCrypto.kt
// Listing 29.5 — Kotlin: streaming attachment encryptor/decryptor with FIXED buffers — the
// STREAM construction chosen in Ch 21 §21.5, byte-compatible with Listing 21.4: a 7-byte random
// nonce prefix, then 64 KiB chunks, each AES-256-GCM with nonce = prefix ‖ counter (u32) ‖ last
// flag. Decryption writes to a temp file and releases it (atomic rename) only when the final
// chunk has verified; a truncated, reordered or modified blob never becomes a visible file.
package example.murmur.attachments

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object AttachmentCrypto {
    const val BUF = 64 * 1024
    private const val TAG = 16

    private fun nonce(prefix: ByteArray, i: Int, last: Boolean) =
        prefix + byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte(), if (last) 1 else 0)

    /** Reads `src` until EOF with one 64 KiB look-ahead; returns (key, SHA-256 of ciphertext, size). */
    fun encrypt(src: InputStream, dst: OutputStream): Triple<ByteArray, ByteArray, Long> {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val prefix = ByteArray(7).also { SecureRandom().nextBytes(it) }
        val digest = MessageDigest.getInstance("SHA-256")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        var cur = ByteArray(BUF); var nxt = ByteArray(BUF)        // the only plaintext buffers
        val out = ByteArray(BUF + TAG)                            // the only ciphertext buffer
        fun emit(b: ByteArray, n: Int) { dst.write(b, 0, n); digest.update(b, 0, n) }
        emit(prefix, prefix.size)
        var size = prefix.size.toLong()
        var curLen = src.readFully(cur); var i = 0
        while (true) {
            val nxtLen = src.readFully(nxt)
            val last = nxtLen == 0
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce(prefix, i, last)))
            val n = cipher.doFinal(cur, 0, curLen, out, 0)
            emit(out, n); size += n
            if (last) break
            cur = nxt.also { nxt = cur }; curLen = nxtLen; i++
        }
        cur.fill(0); nxt.fill(0)
        return Triple(key, digest.digest(), size)
    }

    /** Verify-before-release: plaintext goes to `dst.partial`, renamed to `dst` only at the end. */
    fun decrypt(src: InputStream, key: ByteArray, dst: File) {
        val tmp = File(dst.path + ".partial")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val prefix = ByteArray(7).also { require(src.readFully(it) == 7) { "truncated header" } }
        var cur = ByteArray(BUF + TAG); var nxt = ByteArray(BUF + TAG)
        val out = ByteArray(BUF)
        try {
            tmp.outputStream().use { o ->
                var curLen = src.readFully(cur); var i = 0
                while (true) {
                    val nxtLen = src.readFully(nxt)
                    val last = nxtLen == 0                        // finality is IN the nonce: truncation fails
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, nonce(prefix, i, last)))
                    val n = cipher.doFinal(cur, 0, curLen, out, 0) // throws AEADBadTagException on any change
                    o.write(out, 0, n)
                    if (last) break
                    cur = nxt.also { nxt = cur }; curLen = nxtLen; i++
                }
            }
            check(tmp.renameTo(dst))                              // release: all chunks verified
        } catch (e: AEADBadTagException) {
            tmp.delete(); throw SecurityException("attachment failed authentication; nothing released")
        } finally { out.fill(0) }
    }
}

/** Fill `buf` from the stream (short reads happen); returns bytes read, 0 at EOF. */
private fun InputStream.readFully(buf: ByteArray): Int {
    var n = 0
    while (n < buf.size) { val r = read(buf, n, buf.size - n); if (r < 0) break; n += r }
    return n
}
