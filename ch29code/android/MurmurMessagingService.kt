// MurmurMessagingService.kt
// Listing 29.10 — Kotlin: the FCM high-priority data-message handler. onMessageReceived has
// about 10 seconds and must not do network or crypto work that could outlast them, so it hands
// off to an EXPEDITED WorkManager job that runs the same receive pipeline (one transaction per
// envelope, ack after commit) and posts the notification only after local decryption.
package example.murmur.push

import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import example.murmur.MurmurApp
import example.murmur.R

class MurmurMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        // The payload is {"v":"1"} and nothing else: there is nothing in it to display or trust.
        WorkManager.getInstance(this).enqueueUniqueWork(
            "murmur.receive", ExistingWorkPolicy.APPEND_OR_REPLACE,
            OneTimeWorkRequestBuilder<ReceiveWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .build())
    }

    override fun onNewToken(token: String) {
        (application as MurmurApp).session.updatePushToken(token)   // PUT on the next token request
    }
}

class ReceiveWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as MurmurApp
        if (!app.session.isEnrolled) return Result.success()
        return try {
            val newMessages = app.pipeline.receive()                 // Listing 29.3: decrypt → commit → ack
            if (newMessages > 0) notifyAfterDecrypt(app)
            Result.success()
        } catch (e: java.io.IOException) {
            Result.retry()
        }
    }

    private fun notifyAfterDecrypt(app: MurmurApp) {
        val latest = app.db.messages().latestUnnotified() ?: return
        val text = if (app.prefs.showPreviews) latest.text else app.getString(R.string.new_message)
        val n = NotificationCompat.Builder(app, "messages")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.contacts.displayName(latest.sender))
            .setContentText(text)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)   // lock screen shows the public version
            .setPublicVersion(NotificationCompat.Builder(app, "messages")
                .setSmallIcon(R.drawable.ic_notification).setContentTitle("Murmur")
                .setContentText(app.getString(R.string.new_message)).build())
            .build()
        app.getSystemService(NotificationManager::class.java).notify(latest.conversation.hashCode(), n)
        app.db.messages().markNotified(latest.clientMessageId)
    }

    override suspend fun getForegroundInfo() = (applicationContext as MurmurApp).receivingForegroundInfo()
}
