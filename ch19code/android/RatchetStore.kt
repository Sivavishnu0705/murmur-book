// RatchetStore.kt — canonical stack: SQLCipher DB (key wrapped by Keystore), no-backup dir.
import androidx.room.*
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.util.concurrent.ConcurrentHashMap

@Entity(tableName = "sessions")
data class SessionRow(
    @PrimaryKey val peerDevice: String,
    val state: ByteArray,          // serialized RatchetState (from the Rust core); never logged
    val version: Long              // monotonically increasing; detects lost updates in tests
)

@Entity(tableName = "messages")
data class MessageRow(@PrimaryKey val id: String, val peerDevice: String, val body: ByteArray, val ts: Long)

@Dao interface SessionDao {
    @Query("SELECT * FROM sessions WHERE peerDevice = :peer") fun load(peer: String): SessionRow?
    @Upsert fun save(row: SessionRow)
    @Insert(onConflict = OnConflictStrategy.ABORT) fun insertMessage(m: MessageRow)   // dedupe by id
}

@Database(entities = [SessionRow::class, MessageRow::class], version = 1)
abstract class MurmurDb : RoomDatabase() {
    abstract fun sessions(): SessionDao
    companion object {
        fun open(ctx: android.content.Context, passphrase: ByteArray): MurmurDb {
            System.loadLibrary("sqlcipher")
            val file = java.io.File(ctx.noBackupFilesDir, "murmur.db")   // + dataExtractionRules exclude
            return Room.databaseBuilder(ctx, MurmurDb::class.java, file.path)
                .openHelperFactory(SupportOpenHelperFactory(passphrase))   // passphrase: Keystore-unwrapped
                .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                .build()
        }
    }
}

class RatchetStore(private val db: MurmurDb, private val core: MurmurCore) {
    private val locks = ConcurrentHashMap<String, Mutex>()
    private fun lock(peer: String) = locks.getOrPut(peer) { Mutex() }

    /** decrypt → persist new state + message → commit. Nothing is persisted if decryption fails. */
    suspend fun receive(peer: String, msgId: String, envelope: ByteArray): ByteArray? = lock(peer).withLock {
        db.withTransaction {                                  // Room: a write transaction (IMMEDIATE in WAL mode)
            val row = db.sessions().load(peer) ?: return@withTransaction null
            val result = try {
                core.ratchetDecrypt(row.state, envelope)       // pure function: old state → (new state, pt)
            } catch (e: RatchetException) {
                return@withTransaction null                    // forged/duplicate: state untouched
            }
            db.sessions().save(SessionRow(peer, result.newState, row.version + 1))
            db.sessions().insertMessage(MessageRow(msgId, peer, result.plaintext, System.currentTimeMillis()))
            result.plaintext
        }                                                      // COMMIT here; only then ack to server
    }

    /** Advance and persist the sending chain together with the outgoing record, THEN send. */
    suspend fun prepareSend(peer: String, msgId: String, plaintext: ByteArray): ByteArray = lock(peer).withLock {
        db.withTransaction {
            val row = requireNotNull(db.sessions().load(peer))
            val r = core.ratchetEncrypt(row.state, plaintext)
            db.sessions().save(SessionRow(peer, r.newState, row.version + 1))
            Outbox.put(msgId, r.envelope)                      // retries resend THIS envelope, never re-encrypt
            r.envelope
        }
    }
}
