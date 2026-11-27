// MurmurPushService.kt — data message {"v":"1"}: no sender, no text, no
// conversation id.
import android.app.NotificationManager
import androidx.core.app.NotificationCompat
import androidx.work.*
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class MurmurPushService : FirebaseMessagingService() {
    override fun onMessageReceived(msg: RemoteMessage) {
        // ignore anything unexpected
        if (msg.data["v"] != "1") return
        // Fetching + decrypting may exceed onMessageReceived's window: hand off
        // to an expedited job.
        WorkManager.getInstance(this).enqueueUniqueWork("fetch-messages",
            ExistingWorkPolicy.APPEND_OR_REPLACE,
            OneTimeWorkRequestBuilder<FetchWorker>()
                .setExpedited(
                OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .build())
    }

    override fun onNewToken(token: String) {
        // over the authenticated session
        MurmurCore.get(this).registerPushToken(token)
    }
}

class FetchWorker(ctx: android.content.Context,
    p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        val core = MurmurCore.get(applicationContext)
        val envelopes = runCatching { core.relay.fetchQueued(
            limit = 20) }.getOrElse { return Result.retry() }
        for (env in envelopes) {
            // unseal → verify sender cert → Double Ratchet decrypt + persist in
            // one transaction (Listing 19.3); ack to the relay only after
            // commit.
            val m = core.receive(env) ?: continue
            if (m.isUserVisible) notify(m)
        }
        return Result.success()
    }

    private fun notify(m: DecryptedMessage) {
        val n = NotificationCompat.Builder(applicationContext, "messages")
            .setSmallIcon(R.drawable.ic_murmur)
            // composed on device
            .setContentTitle(m.senderDisplayName)
            .setContentText(if (
                m.previewsEnabled) m.previewText else "New message")
            // lock screen shows a redacted version
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(NotificationCompat.Builder(applicationContext,
                "messages")
                .setSmallIcon(R.drawable.ic_murmur).setContentTitle(
                "Murmur").setContentText("New message").build())
            .setGroup(m.conversationId)
            .build()
        applicationContext.getSystemService(
            NotificationManager::class.java).notify(m.conversationId.hashCode(),
            n)
    }
}
