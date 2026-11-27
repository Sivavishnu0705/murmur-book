// MurmurStorage.kt
// Listing 28.6 — Kotlin: the Android storage stack — a random SQLCipher
// passphrase wrapped by the Keystore key (Listing 28.4), stored in
// noBackupFilesDir; Room on SQLCipher in WAL mode; and the wipe used on logout
// and remote revocation: key first, then files.
package example.murmur.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import example.murmur.identity.KeystoreKeyWrap
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File
import java.security.SecureRandom

private const val DB_KEY_LABEL = "murmur/v1/db-key-wrap"

class DatabaseKey(private val ctx: Context, private val wrap: KeystoreKeyWrap) {
    // noBackupFilesDir: never included in cloud backup or device-to-device
    // transfer.
    private val file = File(ctx.noBackupFilesDir, "dbkey.wrapped")

    /** Returns the raw 32-byte key. The caller wipes it once SQLCipher has its
     * passphrase. */
    fun get(): ByteArray {
        if (!file.exists()) {
            val k = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val tmp = File(file.path + ".tmp")
            tmp.writeBytes(wrap.wrap(DB_KEY_LABEL, k.copyOf()))
            // atomic: never a half-written key file
            check(tmp.renameTo(file))
            return k
        }
        return wrap.unwrap(DB_KEY_LABEL, file.readBytes())
    }
}

@Database(entities = [MessageRow::class, ConversationRow::class], version = 1,
    exportSchema = true)
abstract class AppDatabase : RoomDatabase() {
    abstract fun messages(): MessageDao }

object MurmurStorage {
    fun open(ctx: Context, wrap: KeystoreKeyWrap): AppDatabase {
        System.loadLibrary("sqlcipher")
        val raw = DatabaseKey(ctx, wrap).get()
        // "x'…'" tells SQLCipher this is a raw key: no PBKDF2 (the key is
        // already random).
        val passphrase = "x'${raw.toHex()}'".toByteArray().also { raw.fill(0) }
        // sqlcipher-android keeps `passphrase` for as long as the database can
        // be reopened; only the raw key is wiped here. (The third argument
        // enables WAL, matching setJournalMode below.)
        val factory = SupportOpenHelperFactory(passphrase, null,
            /* enableWriteAheadLogging = */ true)
        return Room.databaseBuilder(ctx, AppDatabase::class.java,
            File(ctx.noBackupFilesDir, "app.db").path)
            .openHelperFactory(factory)
            .setJournalMode(RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING)
            .build()
        // murmur-core opens its own core.db next to it with a second key from
        // the same pattern (label "murmur/v1/db-key-wrap/core"), passed to
        // MurmurCore.open (Listing 26.2).
    }

    /** Logout and remote revocation. Order matters: once the Keystore entry is
     * gone, every file
     *  below is undecryptable, so a crash or kill part-way through leaks
     *  nothing. */
    fun wipe(ctx: Context, db: AppDatabase?, wrap: KeystoreKeyWrap) {
        db?.close()
        // 1. the key (one Keystore entry)
        wrap.destroy()
        listOf("dbkey.wrapped", "app.db", "app.db-wal", "app.db-shm", "core.db",
            "core.db-wal", "core.db-shm")
            .forEach { File(ctx.noBackupFilesDir, it).delete() } // 2. the files
        ctx.getSharedPreferences("murmur",
            Context.MODE_PRIVATE).edit().clear().commit()
    }
}

private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
