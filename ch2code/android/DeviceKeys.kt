// DeviceKeys.kt — hardware-backed P-256 signing key (used later for DPoP /
// attestation)
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

object DeviceKeys {
    private const val ALIAS = "murmur_device_p256"

    fun getOrCreate(context: Context): KeyPair {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let {
            return KeyPair(it.certificate.publicKey, it.privateKey)
        }
        val wantStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(strongBox = wantStrongBox)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)          // fall back to the TEE
        }
    }

    private fun generate(strongBox: Boolean): KeyPair {
        val spec = KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_SIGN)
            // P-256
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // ES256 only
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply { if (
                strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                         setIsStrongBoxBacked(true) }
            .build()
        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    /** Where does the key actually live? Log this; never assume. (API 31+) */
    fun securityLevel(privateKey: PrivateKey): Int? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val factory = KeyFactory.getInstance(privateKey.algorithm,
                "AndroidKeyStore")
            factory.getKeySpec(privateKey, KeyInfo::class.java).securityLevel
            // KeyProperties.SECURITY_LEVEL_STRONGBOX / _TRUSTED_ENVIRONMENT /
            // _SOFTWARE
        } else null

    /** Sign with the hardware key. Output is DER-encoded ECDSA (convert to raw
     * r‖s for JWS). */
    fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
}
