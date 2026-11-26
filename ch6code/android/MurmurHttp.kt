// MurmurHttp.kt — TLS 1.3 only, no cleartext, no fallback spec.
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.TlsVersion

private val TLS13_ONLY: ConnectionSpec =
    ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)   // modern suites only
        .tlsVersions(TlsVersion.TLS_1_3)
        .build()

val murmurHttp: OkHttpClient = OkHttpClient.Builder()
    // Exactly ONE spec. OkHttp retries a failed handshake with the next spec in the list,
    // so adding COMPATIBLE_TLS "for old networks" would create a downgrade path.
    .connectionSpecs(listOf(TLS13_ONLY))
    .build()

// In debug builds and tests, assert what was actually negotiated:
fun assertTls13(url: String) {
    murmurHttp.newCall(Request.Builder().url(url).build()).execute().use { resp ->
        check(resp.handshake?.tlsVersion == TlsVersion.TLS_1_3) {
            "expected TLS 1.3, got ${resp.handshake?.tlsVersion}"
        }
    }
}
