// MessagePipeline.kt
// Listing 29.3 — Kotlin: the send and receive pipelines on Android. murmur-core
// does the cryptography and the persistence inside ONE `BEGIN IMMEDIATE`
// transaction (Listing 29.2 is the same logic, executable); this layer owns
// ordering: nothing is acknowledged before the core has committed, and nothing
// is sent before the core has committed the outbox row.
package example.murmur.messaging

import example.murmur.core.CoreException
import example.murmur.core.Decrypted
import example.murmur.core.MurmurCore
import example.murmur.core.Trust
import example.murmur.net.MurmurApiClient
import example.murmur.storage.AppDatabase
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

class MessagePipeline(
    private val core: MurmurCore,
    private val api: MurmurApiClient,
    private val db: AppDatabase,
    private val ui: ConversationEvents,
) {
    // one receive loop per process; the DB lock covers processes
    private val receiveLock = Mutex()

    /** SEND: encrypt for every verified device of `account` + our own other
     * devices, committed
     *  with the outbox row; then deliver. A crash anywhere replays the
     *  outbox, never re-encrypts. */
    suspend fun send(account: String, content: ByteArray) {
        if (core.trust(account) == Trust.CHANGED_FROM_VERIFIED) {
            // §29.6: the user must look at the new safety number
            ui.blockedByKeyChange(account)
            return
        }
        // fetches bundles if needed; encrypts; COMMIT
        core.enqueueOutgoing(account, content)
        flushOutbox()
    }

    suspend fun flushOutbox() {
        // each row: account, route, envelopes, idempotency key
        for (row in core.pendingOutbox()) {
            var envelopes = row.envelopes
            var sealed = row.sealed
            for (attempt in 0 until 3) {
                // NO Authorization and NO DPoP header: the relay must not learn
                // who sends
                val resp = if (sealed)
                    api.sendSealed(row.deliveryToken, body(row.account,
                        envelopes))
                else api.call("POST", "/v1/messages", body(row.account,
                    envelopes))
                val text = resp.body?.string().orEmpty(); resp.close()
                when {
                    resp.code == 202 -> { core.outboxDelivered(row.id); break }
                    resp.code == 409 && "DEVICE_MISMATCH" in text -> {
                        // §29.3: verify the new device list, keep ciphertexts
                        // for devices that remain, encrypt only for new ones.
                        // Throws KeyChangeBlocked if a verified key changed.
                        envelopes = core.repairFanout(row.id,
                            api.deviceList(row.account))
                    }
                    // token changed
                    resp.code == 401 && sealed -> {
                        core.outboxUseIdentifiedRoute(row.id); sealed = false }
                    // transient: WorkManager retries the outbox later
                    else -> break
                }
            }
        }
    }

    /** RECEIVE: fetch → for each envelope, core.decrypt (dedupe, decrypt,
     * persist: ONE transaction)
     *  → only then ack. A failed decrypt is still committed (as a failure
     *  record) and acked,
     *  so one bad envelope cannot block the queue; the core schedules a
     *  session reset. */
    suspend fun receive(): Int = receiveLock.withLock {
        val batch = api.fetchMessages()          // GET /v1/messages, up to 100
        val acked = mutableListOf<ByteArray>()
        for (env in batch) {
            try {
                when (val r = core.decrypt(env.body)) {
                    // idempotent by client_message_id
                    is Decrypted.Message -> db.moveFromCoreInbox(r)
                    // processed already (NSE, or a redelivery)
                    is Decrypted.Duplicate -> Unit
                    is Decrypted.Undecryptable -> ui.showDecryptionErrorNotice(
                        r.sender)
                    // session reset handled in the core
                    is Decrypted.Control -> Unit
                }
                acked += env.guid
            } catch (e: CoreException.Storage) {
                // disk full, DB locked too long: stop, do NOT ack the rest
                break
            }
        }
        // after every commit, never before
        if (acked.isNotEmpty()) api.ack(acked)
        // §29.7: new sessions + re-sends from the send log
        core.runPendingResets(api)
        acked.size
    }

    private fun body(account: String, envs: Map<String,
        ByteArray>) = JSONObject()
        .put("recipient_account", account)
        .put("envelopes", JSONArray(envs.map { (d, b) ->
            JSONObject().put("device", d).put("body",
            Base64.getEncoder().encodeToString(b)) }))
        .toString().toByteArray()
}
