// X3dhInitiator.kt — matches x3dh_vectors.json. Uses Tink's X25519 and HKDF
// primitives.
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519

object X3dh {
    private const val INFO = "Murmur_X3DH_v1"
    private val F = ByteArray(32) { 0xFF.toByte() }
    fun encode(pub: ByteArray) = byteArrayOf(0x05) + pub

    private fun dh(priv: ByteArray, pub: ByteArray): ByteArray =
        X25519.computeSharedSecret(priv, pub).also {
            require(!it.all { b -> b == 0.toByte() }) { "low-order public key" }
        }

    data class Result(val sk: ByteArray, val ad: ByteArray)

    fun initiate(ikA: ByteArray, ikAPub: ByteArray, ekA: ByteArray,
        b: Bundle): Result {
        require(MurmurCore.verifyXeddsa(b.ik, encode(b.spk),
            b.spkSig)) { "bad SPK signature" }
        // DH1 ‖ DH2 ‖ DH3
        var km = dh(ikA, b.spk) + dh(ekA, b.ik) + dh(ekA, b.spk)
        // ‖ DH4
        b.opk?.let { km += dh(ekA, it) }
        val sk = Hkdf.computeHkdf("HMACSHA256", F + km, ByteArray(32),
            INFO.toByteArray(), 32)
        return Result(sk, encode(ikAPub) + encode(b.ik))
    }
}

// Unit test (JVM): load x3dh_vectors.json, run initiate() with the vector keys,
// and assert sk == with_opk.sk and, with b.opk = null, sk == without_opk.sk.
