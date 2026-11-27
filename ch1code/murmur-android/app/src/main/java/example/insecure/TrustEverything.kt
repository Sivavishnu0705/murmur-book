// murmur-android/app/src/main/java/example/insecure/TrustEverything.kt
// ⚠️ INSECURE — FOR ILLUSTRATION ONLY. Never ship this code.

import android.annotation.SuppressLint
import okhttp3.OkHttpClient
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

@SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager") // (1)
class TrustEverythingManager : X509TrustManager {

    // (2) Should throw CertificateException for an untrusted client chain.
    override fun checkClientTrusted(chain: Array<X509Certificate>,
        authType: String) {
        // empty: accepts anything
    }

    // (3) Should validate the server chain to a trusted root. Does nothing.
    override fun checkServerTrusted(chain: Array<X509Certificate>,
        authType: String) {
        // empty: accepts anything — including an attacker's self-signed cert
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

fun insecureOkHttpClient(): OkHttpClient {
    val trustManager = TrustEverythingManager()
    val sslContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
    }
    return OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .hostnameVerifier { _, _ -> true }   // (4) also accepts any hostname
        .build()
}
