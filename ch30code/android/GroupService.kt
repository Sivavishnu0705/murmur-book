// GroupService.kt
// Listing 30.3 — Kotlin (Swift version: GroupService.swift): the group service layer. It is the
// platform half of Listing 30.1: the three callbacks the core needs, and the network side —
// KeyPackages, DS commits with the merge/clear/retry protocol, and the receive loop in which the
// core's MLS batch joins the app's transaction. Names match the UniFFI-generated Kotlin API
// (`uniffi.murmur_groups`), which was generated from the built core.
package example.murmur.groups

import example.murmur.contacts.ContactsDao
import example.murmur.identity.IdentityKeyHolder
import example.murmur.net.MurmurApiClient
import example.murmur.net.StaleEpoch
import uniffi.murmur_groups.CommitOutput
import uniffi.murmur_groups.CredentialBinder
import uniffi.murmur_groups.GroupException
import uniffi.murmur_groups.IdentityDirectory
import uniffi.murmur_groups.Kv
import uniffi.murmur_groups.MlsStore
import uniffi.murmur_groups.MurmurGroups
import uniffi.murmur_groups.Processed
import net.zetetic.database.sqlcipher.SQLiteDatabase

/** mls_kv in core.db. Joins the caller's transaction if one is open (the receive loop). */
class SqlCipherMlsStore(private val db: SQLiteDatabase) : MlsStore {
    init { db.execSQL("CREATE TABLE IF NOT EXISTS mls_kv (k BLOB PRIMARY KEY, v BLOB NOT NULL)") }
    override fun loadAll(): List<Kv> = db.rawQuery("SELECT k, v FROM mls_kv", null).use { c ->
        buildList { while (c.moveToNext()) add(Kv(c.getBlob(0), c.getBlob(1))) } }
    override fun commit(puts: List<Kv>, deletes: List<ByteArray>) {
        val own = !db.inTransaction()
        if (own) db.beginTransactionNonExclusive()      // = BEGIN IMMEDIATE
        try {
            puts.forEach { db.execSQL("INSERT OR REPLACE INTO mls_kv VALUES (?,?)", arrayOf(it.key, it.value)) }
            deletes.forEach { db.execSQL("DELETE FROM mls_kv WHERE k=?", arrayOf(it)) }
            if (own) db.setTransactionSuccessful()
        } catch (e: Exception) {
            throw GroupException.Storage(e.message ?: "write failed")
        } finally { if (own) db.endTransaction() }
    }
}

/** The AS: only devices from AIK-verified device lists (Ch 29 §29.1). No network here. */
class VerifiedDirectory(private val contacts: ContactsDao) : IdentityDirectory {
    override fun identityKey(account: String, device: String): ByteArray? = contacts.verifiedIdentityKey(account, device)
}

/** XEdDSA with the device identity key (unwrapped by the Keystore key for this one call). */
class IdentityBinder(private val ik: IdentityKeyHolder) : CredentialBinder {
    override fun bind(message: ByteArray): ByteArray = ik.xeddsaSign(message)
}

class GroupService(
    private val db: SQLiteDatabase, private val api: MurmurApiClient, private val contacts: ContactsDao,
    private val account: String, private val device: String, private val ik: IdentityKeyHolder,
) {
    private val store = SqlCipherMlsStore(db)
    @Volatile private var core = open()
    private fun open() = MurmurGroups.open(account, device, store, VerifiedDirectory(contacts), IdentityBinder(ik))

    /** A commit through the DS: 202 → merge; 409 STALE_EPOCH → clear, process the winner, rebuild. */
    private suspend fun submit(gid: ByteArray, joiners: List<String> = emptyList(), removed: List<String> = emptyList(),
                               build: () -> CommitOutput): ULong {
        repeat(3) {
            val out = build()
            val members = core.members(gid).filter { it !in removed }.map { it.substringAfter('/') } + joiners
            try {
                api.submitCommit(out.commit, members.distinct(), joiners, out.welcome)
                return core.mergePending(gid)
            } catch (e: StaleEpoch) {
                core.clearPending(gid)
                receive()                                  // the winning commit is in our queue
            } catch (e: Exception) {
                core.clearPending(gid); throw e
            }
        }
        throw IllegalStateException("commit lost the race three times; try later")
    }

    suspend fun create(admins: List<String>, accounts: List<String>): ByteArray {
        val gid = core.createGroup(admins)
        val targets = accounts.flatMap { a -> api.verifiedDevices(a).keys.filter { it != device } }
        val kps = targets.mapNotNull { api.claimKeyPackage(it) }
        submit(gid, joiners = targets) { core.addMembers(gid, kps) }
        return gid
    }

    suspend fun remove(gid: ByteArray, names: List<String>) = submit(gid, removed = names) { core.removeMembers(gid, names) }
    suspend fun selfUpdate(gid: ByteArray) = submit(gid) { core.selfUpdate(gid) }
    suspend fun send(gid: ByteArray, text: String) = api.postGroupMessage(core.encrypt(gid, text.toByteArray()))

    /** §30.5: a new device of OURS was linked — add it to every group we are in. */
    suspend fun addOwnDeviceEverywhere(newDevice: String) = core.groupIds().forEach { gid ->
        val kp = api.claimKeyPackage(newDevice) ?: return@forEach
        submit(gid, joiners = listOf(newDevice)) { core.addMembers(gid, listOf(kp)) }
    }

    /** §30.5: one of OUR devices was revoked — remove it from every group, at once. */
    suspend fun removeOwnDeviceEverywhere(lost: String) = core.groupIds().forEach { gid ->
        val name = "$account/$lost"
        if (name in core.members(gid)) submit(gid, removed = listOf(name)) { core.removeMembers(gid, listOf(name)) }
    }

    /** Receive: MLS processing + inbox + dedupe in ONE transaction, then acknowledge. */
    suspend fun receive(): List<Processed> {
        val out = mutableListOf<Processed>(); val acked = mutableListOf<ByteArray>()
        for (env in api.fetchGroupEnvelopes()) {
            db.beginTransactionNonExclusive()
            try {
                if (!Dedupe.seen(db, env.guid)) {
                    val r = if (env.isWelcome) { val gid = core.join(env.content); Processed.CommitMerged(gid, core.epoch(gid), emptyList(), emptyList()) }
                            else core.process(env.content)
                    when (r) {
                        is Processed.Application -> Inbox.insert(db, r.groupId, r.sender, r.plaintext)
                        is Processed.Rejected -> SecurityLog.groupRejected(db, r.groupId, r.reason)   // shown as a warning
                        is Processed.RemovedFromGroup -> Inbox.markRemoved(db, r.groupId)
                        else -> Unit
                    }
                    out += r
                }
                Dedupe.mark(db, env.guid)
                db.setTransactionSuccessful()
            } catch (e: GroupException) {
                // Undecryptable: roll back, reload the core from the database (memory may be ahead),
                // and record the failure in its own transaction so the queue moves on.
                db.endTransaction(); core = open(); Dedupe.markFailed(db, env.guid); acked += env.guid; continue
            } finally { if (db.inTransaction()) db.endTransaction() }
            acked += env.guid
        }
        if (acked.isNotEmpty()) api.ack(acked)
        return out
    }
}
