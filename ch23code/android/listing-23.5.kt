// Uses the UniFFI-generated bindings (package uniffi.murmur_mls).
import uniffi.murmur_mls.*

class GroupSession(private val mls: MurmurMls, private val ds: DeliveryService,
    private val dir: VerifiedDevices) {

    suspend fun addDevice(groupId: ByteArray, account: String,
        deviceId: String) {
        // one-time, or last resort
        val kp = ds.claimKeyPackage(deviceId)
        // Ch 20
        require(dir.keyPackageMatchesSignedList(account, deviceId,
            kp)) { "AS check failed" }
        // staged, NOT merged
        val out = mls.addMember(kp)
        when (ds.submitCommit(groupId, out.commit)) {
            SubmitResult.ACCEPTED -> {
                mls.mergePending()
                out.welcome?.let { ds.sendWelcome(deviceId, it) }
            }
            // 409: someone else won this epoch
            SubmitResult.CONFLICT -> {
                mls.clearPending()
                // apply the winning commit
                ds.fetch(groupId).forEach { mls.process(it) }
                // retry in the new epoch
                addDevice(groupId, account, deviceId)
            }
        }
    }

    fun onIncoming(wire: ByteArray): String? = when (val p = mls.process(
        wire)) {
        is Processed.Application -> p.plaintext.decodeToString()
        is Processed.CommitMerged -> { showGroupChangedNotice(p.epoch); null }
        Processed.Other -> null
    }

    fun send(groupId: ByteArray, text: String) = ds.send(groupId,
        mls.encrypt(text.encodeToByteArray()))

    // compare out of band
    fun groupSafetyCode(): String = shortCode(mls.epochAuthenticator())
}
