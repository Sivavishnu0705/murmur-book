// Verification.kt — per-contact trust state. The UI renders `state`; events
// drive transitions.
sealed interface Trust {
    // TOFU: first key accepted, not compared
    data object Unverified : Trust
    // user scanned/compared the safety number
    data object Verified : Trust
    // key changed; contact was never verified
    data class ChangedUnverified(val since: Long) : Trust
    // key changed on a VERIFIED contact: blocking
    data class ChangedFromVerified(val since: Long) : Trust
}

sealed interface Event {
    // plain class: ByteArray equality
    class KeyChanged(val newAik: ByteArray, val reason: ChangeReason,
        val at: Long) : Event
    class Scanned(val payload: ByteArray) : Event
    // "I understand" on the notice
    data object UserAcknowledged : Event
}
// from KT/recovery metadata (§20.6)
enum class ChangeReason { REINSTALL_OR_RECOVERY, UNEXPLAINED }

/** `aik` is the contact's account identity key as last accepted; `qrFor(aik)`
 * builds the expected
 *  QR payload (Listing 20.2's qr_payload) from our key and theirs. */
class ContactTrust(private var aik: ByteArray,
    private val qrFor: (ByteArray) -> ByteArray) {
    var state: Trust = Trust.Unverified; private set
    // verified contacts block until re-verified
    val canSend get() = state !is Trust.ChangedFromVerified

    fun on(e: Event): Banner? = when (e) {
        is Event.Scanned ->
            // constant-time, by content
            if (java.security.MessageDigest.isEqual(e.payload, qrFor(aik))) {
                state = Trust.Verified; Banner.VERIFIED
            // never downgrade state on a bad scan
            } else Banner.MISMATCH
        is Event.KeyChanged ->
            // same key re-announced: no-op
            if (java.security.MessageDigest.isEqual(e.newAik, aik)) null
            else {
                // future scans are compared against the NEW key
                aik = e.newAik.copyOf()
                when (state) {
                    Trust.Verified,
                        is Trust.ChangedFromVerified -> {
                        state = Trust.ChangedFromVerified(e.at);
                        Banner.BLOCKING_CHANGED }
                    else -> { state = Trust.ChangedUnverified(e.at);
                        Banner.SAFETY_NUMBER_CHANGED }
                }
            }
        Event.UserAcknowledged -> when (state) {
            is Trust.ChangedUnverified -> { state = Trust.Unverified; null }
            // acknowledging does NOT restore Verified
            else -> null
        }
    }
}
enum class Banner { VERIFIED, MISMATCH, SAFETY_NUMBER_CHANGED,
    BLOCKING_CHANGED }
