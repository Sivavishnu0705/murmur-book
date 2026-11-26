// MurmurEnvelope.kt
// X25519 and HKDF from Tink's `subtle` package (low-level and not covered by Tink's API
// stability guarantees, so pin your Tink version); AEAD from the platform Cipher.
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object MurmurEnvelope {
    private const val VERSION: Byte = 0x01
    private val INFO = "murmur/v1/ch02/envelope".toByteArray(Charsets.US_ASCII)
    // Android (API 28+) names it "ChaCha20/Poly1305/NoPadding"; the desktop JVM (11+), where
    // unit tests run, names it "ChaCha20-Poly1305". Use whichever this platform provides.
    private val TRANSFORMATION = listOf("ChaCha20/Poly1305/NoPadding", "ChaCha20-Poly1305")
        .first { runCatching { Cipher.getInstance(it) }.isSuccess }

    private fun derive(dh: ByteArray, e: ByteArray, r: ByteArray): Pair<ByteArray, ByteArray> {
        require(dh.any { it != 0.toByte() }) { "all-zero X25519 output: low-order public key" }
        val okm = Hkdf.computeHkdf("HMACSHA256", dh, e + r, INFO, 44)
        return okm.copyOfRange(0, 32) to okm.copyOfRange(32, 44)
    }

    private fun aead(mode: Int, key: ByteArray, nonce: ByteArray,
                     aad: ByteArray, input: ByteArray): ByteArray =
        Cipher.getInstance(TRANSFORMATION).run {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(aad)
            doFinal(input)                       // decrypt throws AEADBadTagException on tamper
        }

    /** `ephemeralPriv` is for test vectors ONLY. Production callers omit it. */
    fun seal(recipientPub: ByteArray, plaintext: ByteArray,
             ephemeralPriv: ByteArray = X25519.generatePrivateKey()): ByteArray {
        val e = X25519.publicFromPrivate(ephemeralPriv)
        val dh = X25519.computeSharedSecret(ephemeralPriv, recipientPub)
        val (key, nonce) = derive(dh, e, recipientPub)
        val aad = byteArrayOf(VERSION) + e
        return aad + aead(Cipher.ENCRYPT_MODE, key, nonce, aad, plaintext)
    }

    fun open(recipientPriv: ByteArray, envelope: ByteArray): ByteArray {
        require(envelope.size >= 1 + 32 + 16 && envelope[0] == VERSION) { "malformed envelope" }
        val e = envelope.copyOfRange(1, 33)
        val r = X25519.publicFromPrivate(recipientPriv)
        val dh = X25519.computeSharedSecret(recipientPriv, e)
        val (key, nonce) = derive(dh, e, r)
        return aead(Cipher.DECRYPT_MODE, key, nonce,
                    envelope.copyOfRange(0, 33), envelope.copyOfRange(33, envelope.size))
    }
}
