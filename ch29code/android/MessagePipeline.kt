// MessagePipeline.kt
// Listing 29.3 — Kotlin: the send and receive pipelines on Android. murmur-core does the
// cryptography and the persistence inside ONE `BEGIN IMMEDIATE` transaction (Listing 29.2 is
// the same logic, executable); this layer owns ordering: nothing is acknowledged before the
// core has committed, and nothing is sent before the core has committed the outbox row.
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
    private val receiveLock = Mutex()            // one receive loop per process; the DB lock covers processes

    /** SEND: encrypt for every verified device of `account` + our own other devices, committed
     *  with the outbox row; then deliver. A crash anywhere replays the outbox, never re-encrypts. */
    suspend fun send(account: String, content: ByteArray) {
        if (core.trust(account) == Trust.CHANGED_FROM_VERIFIED) {
            ui.blockedByKeyChange(account)       // §29.6: the user must look at the new safety number
            return
        }
        core.enqueueOutgoing(account, content)   // fetches bundles if needed; encrypts; COMMIT
        flushOutbox()
    }

    suspend fun flushOutbox() {
        for (row in core.pendingOutbox()) {      // each row: account, route, envelopes, idempotency key
            var envelopes = row.envelopes
            var sealed = row.sealed
            for (attempt in 0 until 3) {
                val resp = if (sealed)   // NO Authorization and NO DPoP header: the relay must not learn who sends
                    api.sendSealed(row.deliveryToken, body(row.account, envelopes))
                else api.call("POST", "/v1/messages", body(row.account, envelopes))
                val text = resp.body?.string().orEmpty(); resp.close()
                when {
                    resp.code == 202 -> { core.outboxDelivered(row.id); break }
                    resp.code == 409 && "DEVICE_MISMATCH" in text -> {
                        // §29.3: verify the new device list, keep ciphertexts for devices that remain,
                        // encrypt only for new ones. Throws KeyChangeBlocked if a verified key changed.
                        envelopes = core.repairFanout(row.id, api.deviceList(row.account))
                    }
                    resp.code == 401 && sealed -> { core.outboxUseIdentifiedRoute(row.id); sealed = false }   // token changed
                    else -> break                // transient: WorkManager retries the outbox later
                }
            }
        }
    }

    /** RECEIVE: fetch → for each envelope, core.decrypt (dedupe, decrypt, persist: ONE transaction)
     *  → only then ack. A failed decrypt is still committed (as a failure record) and acked,
     *  so one bad envelope cannot block the queue; the core schedules a session reset. */
    suspend fun receive(): Int = receiveLock.withLock {
        val batch = api.fetchMessages()          // GET /v1/messages, up to 100
        val acked = mutableListOf<ByteArray>()
        for (env in batch) {
            try {
                when (val r = core.decrypt(env.body)) {
                    is Decrypted.Message -> db.moveFromCoreInbox(r)      // idempotent by client_message_id
                    is Decrypted.Duplicate -> Unit                     // processed already (NSE, or a redelivery)
                    is Decrypted.Undecryptable -> ui.showDecryptionErrorNotice(r.sender)
                    is Decrypted.Control -> Unit                       // session reset handled in the core
                }
                acked += env.guid
            } catch (e: CoreException.Storage) {
                break                            // disk full, DB locked too long: stop, do NOT ack the rest
            }
        }
        if (acked.isNotEmpty()) api.ack(acked)   // after every commit, never before
        core.runPendingResets(api)               // §29.7: new sessions + re-sends from the send log
        acked.size
    }

    private fun body(account: String, envs: Map<String, ByteArray>) = JSONObject()
        .put("recipient_account", account)
        .put("envelopes", JSONArray(envs.map { (d, b) ->
            JSONObject().put("device", d).put("body", Base64.getEncoder().encodeToString(b)) }))
        .toString().toByteArray()
}
