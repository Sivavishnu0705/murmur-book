// DeviceMtls.kt
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.net.Socket
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.*
import okhttp3.OkHttpClient

object DeviceMtls {
    private const val ALIAS = "murmur_device_mtls"
    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null) }

    /** 1. Hardware P-256 key bound to the server's single-use challenge.
     * Returns the attestation chain. */
    fun generateAttestedKey(context: Context,
        challenge: ByteArray): List<X509Certificate> {
        // re-enrollment replaces the old key
        keystore().deleteEntry(ALIAS)
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA256: TLS 1.3 CertificateVerify. NONE: signing a precomputed
            // digest (the PoP below, and TLS stacks that hash before calling
            // the key).
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            // → key attestation chain
            .setAttestationChallenge(challenge)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore")
        val wantStrongBox = Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try { kpg.initialize(spec(wantStrongBox)); kpg.generateKeyPair() }
        catch (e: StrongBoxUnavailableException) { kpg.initialize(spec(false));
            kpg.generateKeyPair() }
        return keystore().getCertificateChain(ALIAS).map {
            it as X509Certificate }
    }

    /** 2. Proof of possession: sign SHA-256("murmur/v1/enroll-pop\0" ‖ nonce ‖
     * account). */
    fun proofOfPossession(nonce: ByteArray, accountId: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(
                "murmur/v1/enroll-pop\u0000".toByteArray() + nonce +
                accountId.toByteArray())
        val key = keystore().getKey(ALIAS, null) as PrivateKey
        // the digest is already computed
        return Signature.getInstance("NONEwithECDSA").run {
            // DER-encoded ECDSA (matches Go's VerifyASN1)
            initSign(key); update(digest); sign()
        }
    }

    /** 3. After enrollment: replace the attestation chain with the issued
     * device certificate chain. */
    fun storeIssuedChain(leaf: X509Certificate, devicesCa: X509Certificate) {
        val ks = keystore()
        val key = ks.getKey(ALIAS, null) as PrivateKey
        // key stays in hardware
        ks.setKeyEntry(ALIAS, key, null, arrayOf(leaf, devicesCa))
    }

    /** 4. KeyManager that presents the hardware-backed identity for mTLS. */
    private class KeystoreKeyManager : X509ExtendedKeyManager() {
        override fun chooseClientAlias(keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: Socket?) = ALIAS
        override fun chooseEngineClientAlias(keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            engine: SSLEngine?) = ALIAS
        override fun getCertificateChain(
            alias: String?): Array<X509Certificate>? =
            keystore().getCertificateChain(ALIAS)?.map {
                it as X509Certificate }?.toTypedArray()
        override fun getPrivateKey(
            alias: String?): PrivateKey? = keystore().getKey(ALIAS,
            null) as? PrivateKey
        override fun getClientAliases(keyType: String?,
            issuers: Array<out Principal>?) = arrayOf(ALIAS)
        override fun getServerAliases(keyType: String?,
            issuers: Array<out Principal>?) = null
        override fun chooseServerAlias(keyType: String?,
            issuers: Array<out Principal>?, socket: Socket?) = null
    }

    fun mtlsClient(): OkHttpClient {
        // Platform trust manager: honors Network Security Config, including the
        // per-domain Murmur-root trust anchor for enroll.murmur.example
        // (Chapter 8, Listing 8.1).
        val tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }
        val tm = tmf.trustManagers.first() as X509TrustManager
        val ctx = SSLContext.getInstance("TLS").apply { init(arrayOf(
            KeystoreKeyManager()), arrayOf(tm), null) }
        return OkHttpClient.Builder().sslSocketFactory(ctx.socketFactory,
            tm).build()
    }
}

// Optional: a PKCS#10 CSR, for CAs that require one (Bouncy Castle:
// org.bouncycastle:bcpkix-jdk18on). val signer = object :
// org.bouncycastle.operator.ContentSigner { private val sig =
// Signature.getInstance("SHA256withECDSA").apply { initSign(hardwarePrivateKey)
// } private val out = object : java.io.OutputStream() { override fun write(b:
// Int) = sig.update(b.toByte()) override fun write(b: ByteArray, o: Int, l:
// Int) = sig.update(b, o, l) } override fun getAlgorithmIdentifier() =
// DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA") override
// fun getOutputStream() = out override fun getSignature(): ByteArray =
// sig.sign() }
// val csr = JcaPKCS10CertificationRequestBuilder(X500Name("CN=murmur-device"),
// hardwarePublicKey).build(signer)
