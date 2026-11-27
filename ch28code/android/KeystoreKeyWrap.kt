// KeystoreKeyWrap.kt
// Listing 28.4 — Kotlin: the Android PlatformKeyWrap — an AES-256-GCM key in
// StrongBox (or the TEE) that wraps the X25519/Ed25519 private keys murmur-core
// generates in software, and the database passphrase. The label is GCM
// associated data (Ch 24 registry).
package example.murmur.identity

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import example.murmur.core.CoreException
import example.murmur.core.PlatformKeyWrap
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreKeyWrap(private val ctx: Context) : PlatformKeyWrap {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(
        null) }

    private fun key(): SecretKey = (ks.getKey(ALIAS,
        null) as SecretKey?) ?: create()

    private fun create(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // the Keystore picks every IV: no reuse possible
            .setRandomizedEncryptionRequired(true)
            // background receive while locked needs this key
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore")
        return try {
            gen.init(spec(ctx.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE))); gen.generateKey()
        } catch (e: StrongBoxUnavailableException) { gen.init(spec(false));
            gen.generateKey() }
    }

    override fun wrap(label: String, secret: ByteArray): ByteArray = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(
            Cipher.ENCRYPT_MODE, key()) }
        c.updateAAD(label.toByteArray())
        // 12-byte IV ‖ ciphertext ‖ 16-byte tag
        c.iv + c.doFinal(secret)
    // the core's copy is zeroized on its side too
    } finally { secret.fill(0) }

    override fun unwrap(label: String, blob: ByteArray): ByteArray = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
        c.updateAAD(label.toByteArray())
        c.doFinal(blob, 12, blob.size - 12)
    } catch (e: KeyPermanentlyInvalidatedException) {
        // e.g. after a factory reset of the secure element
        throw CoreException.KeyUnavailable()
    } catch (e: AEADBadTagException) {
        // wrong label or a blob from another key
        throw CoreException.KeyUnavailable()
    }

    /** Remote wipe and logout: deleting this ONE entry makes every wrapped
     * secret unreadable. */
    fun destroy() = ks.deleteEntry(ALIAS)

    companion object { const val ALIAS = "murmur.wrap" }
}
