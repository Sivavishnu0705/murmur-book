// MurmurPinning.kt — OkHttp's pinner (when NSC can't be used, or in shared JVM
// code).
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import javax.net.ssl.SSLPeerUnverifiedException

private val murmurPins = CertificatePinner.Builder()
    // Same three pins as the NSC pin-set. "sha256/" + base64(SHA-256(SPKI))
    .add("api.murmur.example",
        "sha256/pZEWrYb3RXviM6CaMuoD9K45oxRYxl3r6o2wVpxoB/4=")
    .add("api.murmur.example",
        "sha256/EkqLSW6Jl1MM8VzFhqEcKmKP8PtgnnpnTYDD4XC6gOM=")
    .add("api.murmur.example",
        "sha256/EavOPsmWT0hCK0SJ4b77aBV0CjEUTSvCXYTEN0ihacI=")
    .build()

val pinnedClient: OkHttpClient = OkHttpClient.Builder()
    // checked after the platform TrustManager succeeds,
    .certificatePinner(murmurPins)
    .build()                            // against the cleaned (validated) chain

// Pin failures surface as SSLPeerUnverifiedException; its message lists the
// chain's pins.
fun reportIfPinFailure(e: Exception, report: (String) -> Unit) {
    if (e is SSLPeerUnverifiedException && e.message?.contains(
        "Certificate pinning failure") == true) {
        // send to a reporting endpoint on a different, unpinned domain
        report(e.message!!)
    }
}
