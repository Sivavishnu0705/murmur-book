// DPoP.kt
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

/** Unsigned, fixed-length big-endian encoding (JWK coordinates, raw ECDSA r and s). */
private fun BigInteger.fixed(len: Int): ByteArray {
    val b = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
    require(b.size <= len)
    return ByteArray(len - b.size) + b
}

/** DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) → JWS raw r‖s (64 bytes). */
private fun derToRaw(der: ByteArray): ByteArray {
    var i = 2                                         // skip SEQUENCE tag + length (< 128 for P-256)
    if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
    fun int(): BigInteger {
        require(der[i] == 0x02.toByte()); val len = der[i + 1].toInt()
        return BigInteger(1, der.copyOfRange(i + 2, i + 2 + len)).also { i += 2 + len }
    }
    return int().fixed(32) + int().fixed(32)
}

class DPoPKey(private val ctx: Context) {
    private val alias = "murmur-dpop-v1"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** The device's first hardware-bound key: created once, never exported. */
    fun privateKey(): PrivateKey =
        (ks.getKey(alias, null) as? PrivateKey) ?: generate().private

    private fun generate(): KeyPair {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            // No user-authentication requirement: proofs are signed for background sync too.
            // Attestation of this key happens at enrollment (Chapter 9 §9.7).
            .build()
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val hasStrongBox = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try { gen.initialize(spec(hasStrongBox)); gen.generateKeyPair() }
        catch (e: StrongBoxUnavailableException) { gen.initialize(spec(false)); gen.generateKeyPair() }
    }

    fun jwk(): JSONObject {
        val w = (ks.getCertificate(alias).publicKey as ECPublicKey).w
        return JSONObject().put("kty", "EC").put("crv", "P-256")
            .put("x", b64(w.affineX.fixed(32))).put("y", b64(w.affineY.fixed(32)))
    }

    /** RFC 7638 thumbprint, for dpop_jkt in the authorization request. */
    fun thumbprint(): String {
        val j = jwk()
        val canon = """{"crv":"P-256","kty":"EC","x":"${j.getString("x")}","y":"${j.getString("y")}"}"""
        return b64(MessageDigest.getInstance("SHA-256").digest(canon.toByteArray()))
    }

    fun proof(method: String, url: okhttp3.HttpUrl, accessToken: String?, nonce: String?): String {
        val header = JSONObject().put("typ", "dpop+jwt").put("alg", "ES256").put("jwk", jwk())
        val htu = url.newBuilder().query(null).fragment(null).build().toString()   // no query/fragment
        val claims = JSONObject()
            .put("jti", b64(ByteArray(16).also { SecureRandom().nextBytes(it) }))
            .put("htm", method).put("htu", htu)
            .put("iat", System.currentTimeMillis() / 1000)
        accessToken?.let { claims.put("ath", b64(MessageDigest.getInstance("SHA-256").digest(it.toByteArray(Charsets.US_ASCII)))) }
        nonce?.let { claims.put("nonce", it) }
        val input = b64(header.toString().toByteArray()) + "." + b64(claims.toString().toByteArray())
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey()); update(input.toByteArray(Charsets.US_ASCII)); sign()
        }
        return input + "." + b64(derToRaw(der))                                    // JWS wants raw r‖s
    }
}

/** Adds Authorization: DPoP + a fresh proof to every API call; handles server nonces. */
class DPoPInterceptor(private val key: DPoPKey, private val tokens: () -> String?) : Interceptor {
    @Volatile private var nonce: String? = null                // per-server in a real app

    override fun intercept(chain: Interceptor.Chain): Response {
        val response = chain.proceed(sign(chain.request()))
        response.header("DPoP-Nonce")?.let { nonce = it }      // servers may rotate on any response
        val challenge = response.header("WWW-Authenticate").orEmpty()
        if (response.code == 401 && challenge.contains("use_dpop_nonce")) {
            response.close()
            return chain.proceed(sign(chain.request())).also { r -> r.header("DPoP-Nonce")?.let { nonce = it } }
        }
        return response
    }

    private fun sign(req: Request): Request {
        val at = tokens() ?: return req
        return req.newBuilder()
            .header("Authorization", "DPoP $at")
            .header("DPoP", key.proof(req.method, req.url, at, nonce))   // never reuse a proof
            .build()
    }
}
