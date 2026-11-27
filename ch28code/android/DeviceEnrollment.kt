// DeviceEnrollment.kt
// Listing 28.1 — Kotlin: device enrollment on Android — the hardware DPoP key
// with a key attestation bound to murmur-auth's nonce, a Play Integrity verdict
// bound to the same nonce and key, and the proof of possession. The three go
// with the first token request (Listing 27.3).
package example.murmur.identity

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
    .PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager
    .StandardIntegrityTokenRequest
import kotlinx.coroutines.tasks.await
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

class DeviceEnrollment(private val ctx: Context,
    private val cloudProjectNumber: Long) {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(
        null) }

    /** 1. The DPoP key: P-256, non-exportable, StrongBox when the device has
     * one, else the TEE.
     *  No user authentication: the key must sign DPoP proofs for background
     *  fetches while the
     *  phone is locked (FCM wake → fetch → decrypt, Ch 21 §21.4). */
    fun createDpopKey(nonce: ByteArray): List<X509Certificate> {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(DPOP_ALIAS,
            KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // the attestation chain proves THIS key, for THIS nonce
            .setAttestationChallenge(nonce)
            .setIsStrongBoxBacked(strongBox)
            .build()
        // a new enrollment always means a new key
        ks.deleteEntry(DPOP_ALIAS)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore")
        val strongBox = ctx.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            kpg.initialize(spec(strongBox)); kpg.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            // the attestation records which one it was
            kpg.initialize(spec(false)); kpg.generateKeyPair()
        }
        return ks.getCertificateChain(DPOP_ALIAS).map { it as X509Certificate }
    }

    /** 2. Play Integrity (standard request): requestHash binds the verdict to
     * nonce ‖ SPKI. */
    suspend fun integrityToken(nonce: ByteArray, spki: ByteArray): String {
        val manager = IntegrityManagerFactory.createStandard(ctx)
        val provider = manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(
            cloudProjectNumber).build()).await()
        val hash = MessageDigest.getInstance("SHA-256").digest(
            nonce + spki).toHex()
        return provider.request(
            StandardIntegrityTokenRequest.builder().setRequestHash(
            hash).build()).await().token()
    }

    /** 3. Proof of possession over "murmur/v1/enroll-pop\0" ‖ nonce ‖ account
     * (Ch 9 §9.7). */
    fun proofOfPossession(nonce: ByteArray, account: String): ByteArray {
        val key = ks.getKey(DPOP_ALIAS, null) as PrivateKey
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(
                "murmur/v1/enroll-pop\u0000".toByteArray() + nonce +
                account.toByteArray()); sign()
        }
        // Murmur and JWS use raw r‖s, 64 bytes
        return derToRaw(der)
    }

    companion object { const val DPOP_ALIAS = "murmur.dpop" }
}

/** DER ECDSA-Sig-Value → raw 64-byte r‖s, with strict DER checks. The input
 * comes from our own
 *  Keystore, but a converter that accepts malformed DER is a
 *  parser-differential waiting to
 *  happen if it is ever reused on untrusted input: so every tag, length and
 *  integer is checked. */
fun derToRaw(der: ByteArray): ByteArray {
    fun bad(): Nothing = throw IllegalArgumentException(
        "malformed ECDSA signature")
    var i = 0
    fun byte(): Int = if (i < der.size) der[i++].toInt() and 0xff else bad()
    // DER: short form, or 0x81 + one byte ≥ 0x80
    fun length(): Int {
        val b = byte()
        return when {
            b < 0x80 -> b
            // non-minimal long form is not DER
            b == 0x81 -> byte().also { if (it < 0x80) bad() }
            // a P-256 signature is never longer than 255 B
            else -> bad()
        }
    }
    fun scalar(): ByteArray {
        if (byte() != 0x02) bad()                        // INTEGER
        val len = length()
        if (len == 0 || len > 33 || i + len > der.size) bad()
        val v = der.copyOfRange(i, i + len); i += len
        // negative: never valid for r or s
        if (v[0].toInt() and 0x80 != 0) bad()
        // non-minimal padding
        if (len > 1 && v[0].toInt() == 0 && v[1].toInt() and 0x80 == 0) bad()
        val t = if (v[0].toInt() == 0 && len > 1) v.copyOfRange(1, len) else v
        // > 256 bits, or zero
        if (t.size > 32 || t.all { it.toInt() == 0 }) bad()
        return ByteArray(32 - t.size) + t
    }
    if (byte() != 0x30) bad()                            // SEQUENCE
    // exact length, no trailing bytes
    if (length() != der.size - i) bad()
    val r = scalar(); val s = scalar()
    if (i != der.size) bad()
    // range checks (r, s < n) happen in the verifier
    return r + s
}

fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
