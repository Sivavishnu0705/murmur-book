// LocalSecrets.kt — AEAD for small local blobs (drafts, cached tokens).
// Dependency: com.google.crypto.tink:tink-android (check for the current version)
import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager

object LocalSecrets {
    private const val KEYSET_NAME = "murmur_local_aead_keyset"   // SharedPreferences key
    private const val PREF_FILE = "murmur_crypto_prefs"
    // The keyset is stored encrypted under this non-exportable Keystore key.
    private const val MASTER_KEY_URI = "android-keystore://murmur_local_master_key"

    @Volatile private var cached: Aead? = null

    fun aead(context: Context): Aead = cached ?: synchronized(this) {
        cached ?: run {
            AeadConfig.register()
            val handle = AndroidKeysetManager.Builder()
                .withSharedPref(context.applicationContext, KEYSET_NAME, PREF_FILE)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .keysetHandle
            // Older Tink versions: handle.getPrimitive(Aead::class.java)
            handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
                .also { cached = it }
        }
    }
}

// Usage: bind the ciphertext to its purpose and location with associated data.
fun saveDraft(context: Context, conversationId: Long, text: String): ByteArray {
    val aad = "murmur/v1/local/draft:conversation=$conversationId".toByteArray()
    return LocalSecrets.aead(context).encrypt(text.toByteArray(), aad)
}

fun loadDraft(context: Context, conversationId: Long, blob: ByteArray): String {
    val aad = "murmur/v1/local/draft:conversation=$conversationId".toByteArray()
    return String(LocalSecrets.aead(context).decrypt(blob, aad))   // throws on tamper
}
