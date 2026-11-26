// PrekeyWorker.kt
// Listing 28.9 — Kotlin: WorkManager prekey job. Daily, on any network; also enqueued as
// expedited work when a fetch shows the server's stock is low. The work itself is murmur-core's
// maintainPrekeys() — the same logic as Listing 28.11 — so Android and iOS cannot drift apart.
package example.murmur.prekeys

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import example.murmur.MurmurApp
import example.murmur.core.CoreException
import java.util.concurrent.TimeUnit

class PrekeyWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as MurmurApp
        if (!app.session.isEnrolled) return Result.success()        // logged out or wiped: nothing to do
        return try {
            // 1. GET /v1/keys/count  2. top up OPKs/PQ OPKs below the low-water marks
            // 3. rotate SPK + PQ last-resort after 7 days  4. purge private keys > 30 days past use
            // Every upload carries an Idempotency-Key (Listing 28.12), so a retry never duplicates.
            val report = app.core.maintainPrekeys(app.api, (System.currentTimeMillis() / 1000).toULong())
            app.securityLog.record("prekeys", report.summary)       // counts only, no key material
            Result.success()
        } catch (e: CoreException.Network) {                        // the API client's failure, via the core
            Result.retry()                                          // exponential backoff below
        } catch (e: CoreException.KeyUnavailable) {
            app.session.onKeysLost()                                // hardware key gone: re-enroll flow
            Result.failure()
        }
    }

    companion object {
        private val network = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun schedule(ctx: Context) = WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
            "murmur.prekeys", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<PrekeyWorker>(1, TimeUnit.DAYS)
                .setConstraints(network)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
                .build())

        /** Called after a message fetch when the server reports low stock (Listing 27.4 OnLow). */
        fun runSoon(ctx: Context) = WorkManager.getInstance(ctx).enqueueUniqueWork(
            "murmur.prekeys.now", ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<PrekeyWorker>()
                .setConstraints(network)
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .build())
    }
}
