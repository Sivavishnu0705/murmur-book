// SafetyNumberViewModel.kt
// Listing 29.12 — Kotlin (Swift version below): safety-number UI logic. The numbers and QR
// payloads come from murmur-core (Listing 20.2's algorithm: 5,200 SHA-512 iterations over each
// AIK). The UI's job: show them legibly, compare scans exactly, and turn trust state into the
// right amount of friction — none for a first contact, a notice for a change, a stop for a
// change after verification.
package example.murmur.verify

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import example.murmur.core.MurmurCore
import example.murmur.core.Trust
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface Banner {
    object None : Banner
    object Verified : Banner                                   // small check mark in the header
    data class Changed(val account: String) : Banner           // inline notice; sending allowed
    data class ChangedFromVerified(val account: String) : Banner // interstitial; sending blocked
}

class SafetyNumberViewModel(private val core: MurmurCore, private val account: String) : ViewModel() {
    val digits = MutableStateFlow<List<String>>(emptyList())   // 12 groups of 5, shown as 3 rows of 4
    val qr = MutableStateFlow<ByteArray?>(null)
    val banner = MutableStateFlow<Banner>(Banner.None)

    init { refresh() }

    fun refresh() = viewModelScope.launch {
        // 2 × 5,200 SHA-512 iterations: cheap, but never on the main thread.
        val (number, payload) = withContext(Dispatchers.Default) { core.safetyNumber(account) to core.qrPayload(account) }
        digits.value = number.chunked(5)
        qr.value = payload
        banner.value = when (core.trust(account)) {
            Trust.UNVERIFIED -> Banner.None
            Trust.VERIFIED -> Banner.Verified
            Trust.CHANGED_UNVERIFIED -> Banner.Changed(account)
            Trust.CHANGED_FROM_VERIFIED -> Banner.ChangedFromVerified(account)
        }
    }

    /** Camera result. Exact byte-for-byte comparison in the core; never "close enough". */
    fun onScanned(scanned: ByteArray): Boolean {
        val ok = core.markVerified(account, scanned)
        refresh()
        return ok                                              // false: "These numbers don't match"
    }

    /** "I've seen the change" on the interstitial: allows sending again, but NOT verified. */
    fun acknowledgeChange() { core.acknowledgeKeyChange(account); refresh() }
}

/* ── Swift (iOS), same logic ─────────────────────────────────────────────────────────────────
@MainActor final class SafetyNumberModel: ObservableObject {
    @Published var groups: [String] = []
    @Published var qr: Data?
    @Published var banner: Banner = .none
    enum Banner { case none, verified, changed(String), changedFromVerified(String) }
    private let core: MurmurCore, account: String
    init(core: MurmurCore, account: String) { self.core = core; self.account = account; Task { await refresh() } }

    func refresh() async {
        let (n, p) = await Task.detached { [core, account] in ((try? core.safetyNumber(account: account)) ?? "",
                                                              core.qrPayload(account: account)) }.value
        groups = stride(from: 0, to: n.count, by: 5).map {
            String(n[n.index(n.startIndex, offsetBy: $0)..<n.index(n.startIndex, offsetBy: $0 + 5)]) }
        qr = p
        switch core.trust(account: account) {
        case .unverified: banner = .none
        case .verified: banner = .verified
        case .changedUnverified: banner = .changed(account)
        case .changedFromVerified: banner = .changedFromVerified(account)
        }
    }
    func scanned(_ payload: Data) async -> Bool { let ok = (try? core.markVerified(account: account, scannedQr: payload)) ?? false; await refresh(); return ok }
    func acknowledgeChange() async { core.acknowledgeKeyChange(account: account); await refresh() }
}
──────────────────────────────────────────────────────────────────────────────────────────── */
