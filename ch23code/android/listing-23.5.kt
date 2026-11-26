// Uses the UniFFI-generated bindings (package uniffi.murmur_mls).
import uniffi.murmur_mls.*

class GroupSession(private val mls: MurmurMls, private val ds: DeliveryService, private val dir: VerifiedDevices) {

    suspend fun addDevice(groupId: ByteArray, account: String, deviceId: String) {
        val kp = ds.claimKeyPackage(deviceId)                       // one-time, or last resort
        require(dir.keyPackageMatchesSignedList(account, deviceId, kp)) { "AS check failed" }   // Ch 20
        val out = mls.addMember(kp)                                  // staged, NOT merged
        when (ds.submitCommit(groupId, out.commit)) {
            SubmitResult.ACCEPTED -> {
                mls.mergePending()
                out.welcome?.let { ds.sendWelcome(deviceId, it) }
            }
            SubmitResult.CONFLICT -> {                               // 409: someone else won this epoch
                mls.clearPending()
                ds.fetch(groupId).forEach { mls.process(it) }        // apply the winning commit
                addDevice(groupId, account, deviceId)                // retry in the new epoch
            }
        }
    }

    fun onIncoming(wire: ByteArray): String? = when (val p = mls.process(wire)) {
        is Processed.Application -> p.plaintext.decodeToString()
        is Processed.CommitMerged -> { showGroupChangedNotice(p.epoch); null }
        Processed.Other -> null
    }

    fun send(groupId: ByteArray, text: String) = ds.send(groupId, mls.encrypt(text.encodeToByteArray()))

    fun groupSafetyCode(): String = shortCode(mls.epochAuthenticator())   // compare out of band
}
