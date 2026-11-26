// Verification.kt — per-contact trust state. The UI renders `state`; events drive transitions.
sealed interface Trust {
    data object Unverified : Trust                                // TOFU: first key accepted, not compared
    data object Verified : Trust                                  // user scanned/compared the safety number
    data class ChangedUnverified(val since: Long) : Trust         // key changed; contact was never verified
    data class ChangedFromVerified(val since: Long) : Trust       // key changed on a VERIFIED contact: blocking
}

sealed interface Event {
    class KeyChanged(val newAik: ByteArray, val reason: ChangeReason, val at: Long) : Event   // plain class: ByteArray equality
    class Scanned(val payload: ByteArray) : Event
    data object UserAcknowledged : Event                           // "I understand" on the notice
}
enum class ChangeReason { REINSTALL_OR_RECOVERY, UNEXPLAINED }     // from KT/recovery metadata (§20.6)

/** `aik` is the contact's account identity key as last accepted; `qrFor(aik)` builds the expected
 *  QR payload (Listing 20.2's qr_payload) from our key and theirs. */
class ContactTrust(private var aik: ByteArray, private val qrFor: (ByteArray) -> ByteArray) {
    var state: Trust = Trust.Unverified; private set
    val canSend get() = state !is Trust.ChangedFromVerified       // verified contacts block until re-verified

    fun on(e: Event): Banner? = when (e) {
        is Event.Scanned ->
            if (java.security.MessageDigest.isEqual(e.payload, qrFor(aik))) {    // constant-time, by content
                state = Trust.Verified; Banner.VERIFIED
            } else Banner.MISMATCH                                // never downgrade state on a bad scan
        is Event.KeyChanged ->
            if (java.security.MessageDigest.isEqual(e.newAik, aik)) null       // same key re-announced: no-op
            else {
                aik = e.newAik.copyOf()                     // future scans are compared against the NEW key
                when (state) {
                    Trust.Verified, is Trust.ChangedFromVerified -> { state = Trust.ChangedFromVerified(e.at); Banner.BLOCKING_CHANGED }
                    else -> { state = Trust.ChangedUnverified(e.at); Banner.SAFETY_NUMBER_CHANGED }
                }
            }
        Event.UserAcknowledged -> when (state) {
            is Trust.ChangedUnverified -> { state = Trust.Unverified; null }
            else -> null                                           // acknowledging does NOT restore Verified
        }
    }
}
enum class Banner { VERIFIED, MISMATCH, SAFETY_NUMBER_CHANGED, BLOCKING_CHANGED }
