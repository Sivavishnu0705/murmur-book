// HostnameVerification.kt
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession
import okhttp3.OkHttpClient

// ✓ RIGHT (almost always): don't set a hostname verifier at all.
// OkHttp's default verifier matches the certificate's SANs against the URL's host,
// with correct wildcard and IP rules.
val murmurClient: OkHttpClient = OkHttpClient.Builder().build()

// ✓ RIGHT, if you genuinely need an extra rule: DECORATE the default verifier.
// The default check must pass first; your rule can only narrow what is accepted.
class OnlyMurmurHosts(
    private val allowed: Set<String>,
    private val delegate: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier(),
) : HostnameVerifier {
    override fun verify(hostname: String, session: SSLSession): Boolean =
        delegate.verify(hostname, session) && hostname in allowed
}

// ⚠️ INSECURE — FOR ILLUSTRATION ONLY. Accepts any certificate for any host.
val insecure1 = OkHttpClient.Builder()
    .hostnameVerifier { _, _ -> true }
    .build()

// ⚠️ INSECURE — FOR ILLUSTRATION ONLY. Looks like a check; checks nothing.
// `hostname` is the name the APP asked for, not a name from the certificate,
// so this is always true for Murmur's own requests — whatever the server presented.
val insecure2 = OkHttpClient.Builder()
    .hostnameVerifier { hostname, _ -> hostname.endsWith(".murmur.example") }
    .build()
