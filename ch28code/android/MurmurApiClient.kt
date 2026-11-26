// MurmurApiClient.kt
// Listing 28.12 — Kotlin: DPoP-enabled API client on OkHttp. Pinning comes from the network
// security config (Listing 8.1) plus OkHttp's CertificatePinner for the same pins (Listing 8.2).
// Every attempt gets a FRESH DPoP proof (new jti, current nonce); every state-changing request
// gets ONE Idempotency-Key that all its retries reuse.
package example.murmur.net

import example.murmur.identity.DeviceEnrollment
import example.murmur.identity.derToRaw
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

class MurmurApiClient(private val tokens: TokenProvider) {
    private val origin = "https://api.murmur.example"
    private val nonce = AtomicReference<String?>(null)              // last DPoP-Nonce from the server
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    private val http = OkHttpClient.Builder()
        .certificatePinner(CertificatePinner.Builder()               // the same three pins as Listing 8.2
            .add("api.murmur.example", "sha256/pZEWrYb3RXviM6CaMuoD9K45oxRYxl3r6o2wVpxoB/4=")
            .add("api.murmur.example", "sha256/EkqLSW6Jl1MM8VzFhqEcKmKP8PtgnnpnTYDD4XC6gOM=")
            .add("api.murmur.example", "sha256/EavOPsmWT0hCK0SJ4b77aBV0CjEUTSvCXYTEN0ihacI=")
            .build())
        .retryOnConnectionFailure(false)                            // retries are OURS, with the same key
        .build()

    private val dpopKey: PrivateKey get() = KeyStore.getInstance("AndroidKeyStore").run {
        load(null); getKey(DeviceEnrollment.DPOP_ALIAS, null) as PrivateKey }
    private val jwk: JSONObject by lazy {
        val pub = KeyStore.getInstance("AndroidKeyStore").run { load(null); getCertificate(DeviceEnrollment.DPOP_ALIAS).publicKey } as ECPublicKey
        fun coord(v: java.math.BigInteger) = b64.encodeToString(v.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it })
        JSONObject().put("kty", "EC").put("crv", "P-256").put("x", coord(pub.w.affineX)).put("y", coord(pub.w.affineY))
    }

    /** RFC 9449 proof: header {typ, alg, jwk}, claims {jti, htm, htu, iat, ath, nonce?}. */
    private fun proof(method: String, path: String, accessToken: String): String {
        val header = JSONObject().put("typ", "dpop+jwt").put("alg", "ES256").put("jwk", jwk)
        val claims = JSONObject().put("jti", UUID.randomUUID().toString()).put("htm", method)
            .put("htu", origin + path).put("iat", System.currentTimeMillis() / 1000)
            .put("ath", b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray())))
        nonce.get()?.let { claims.put("nonce", it) }
        val input = b64.encodeToString(header.toString().toByteArray()) + "." + b64.encodeToString(claims.toString().toByteArray())
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(dpopKey); update(input.toByteArray()); sign() }
        return input + "." + b64.encodeToString(derToRaw(der))
    }

    suspend fun call(method: String, path: String, body: ByteArray? = null): Response {
        val idempotencyKey = if (method == "POST" || method == "PUT") UUID.randomUUID().toString() else null
        var refreshed = false
        var nonceRetried = false
        for (attempt in 0 until 4) {
            val at = tokens.accessToken()                            // in memory only; 5-minute lifetime
            val req = Request.Builder().url(origin + path)
                .method(method, body?.toRequestBody())
                .header("Authorization", "DPoP $at")
                .header("DPoP", proof(method, path, at))             // new jti on every attempt
                .apply { idempotencyKey?.let { header("Idempotency-Key", it) } }
                .build()
            val resp = try { withContext(Dispatchers.IO) { http.newCall(req).execute() } } catch (e: IOException) {
                if (attempt == 3) throw e
                delay(500L shl attempt); continue                    // lost response: same key, retry
            }
            resp.header("DPoP-Nonce")?.let { nonce.set(it) }
            val challenge = resp.header("WWW-Authenticate").orEmpty()
            when {
                resp.code == 401 && "use_dpop_nonce" in challenge && !nonceRetried -> { nonceRetried = true; resp.close() }
                resp.code == 401 && "insufficient_user_authentication" in challenge -> return resp   // UI runs step-up
                resp.code == 401 && "invalid_token" in challenge && !refreshed -> {
                    refreshed = true; resp.close(); tokens.refresh()  // single-flight (Listing 11.4)
                }
                resp.code in listOf(502, 503, 504) || (resp.code == 429 && attempt < 3) -> {
                    val wait = resp.header("Retry-After")?.toLongOrNull()?.times(1000) ?: (500L shl attempt)
                    resp.close(); delay(wait)
                }
                else -> return resp                                  // success or a final error
            }
        }
        throw IOException("gave up after retries")
    }
}

interface TokenProvider { suspend fun accessToken(): String; suspend fun refresh() }
