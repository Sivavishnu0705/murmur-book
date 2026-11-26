// SessionGuard.kt — forced logout: push is a hint, the server's answer decides.
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import androidx.work.*

class MurmurMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(msg: RemoteMessage) {
        if (msg.data["type"] == "session_revoked") {
            // Don't act on the payload: schedule a verified check over the normal API channel.
            WorkManager.getInstance(this).enqueueUniqueWork("session-check",
                ExistingWorkPolicy.KEEP, OneTimeWorkRequestBuilder<SessionCheckWorker>()
                    .setConstraints(Constraints(requiredNetworkType = NetworkType.CONNECTED)).build())
        }
    }
}

class SessionCheckWorker(ctx: android.content.Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result = when (Session.api.sessionStatus()) {   // GET /v1/session
        SessionStatus.ACTIVE -> Result.success()                                    // spurious hint
        SessionStatus.REVOKED -> { Session.forceSignOut(Reason.REMOTE); Result.success() }
        SessionStatus.UNREACHABLE -> Result.retry()
    }
}

/** Central handling of auth failures, called by the OkHttp Authenticator (Listing 11.4). */
object AuthFailurePolicy {
    fun on401(wwwAuthenticate: String, refreshError: String?): Action = when {
        "insufficient_user_authentication" in wwwAuthenticate -> Action.STEP_UP     // NOT a logout
        "use_dpop_nonce" in wwwAuthenticate -> Action.RETRY_WITH_NONCE             // Ch 13
        refreshError == "attestation_required" -> Action.SHOW_DEVICE_INTEGRITY     // suspend, don't wipe
        refreshError == "invalid_grant" -> Action.FORCE_SIGN_OUT                   // session is gone
        else -> Action.REFRESH_ONCE
    }
}

object Session {
    lateinit var api: MurmurApi
    /** Ends every local layer of Fig 15.1. Idempotent; safe to call from any thread. */
    suspend fun forceSignOut(reason: Reason) {
        runCatching { api.revokeRefreshToken() }        // best-effort RFC 7009; may already be revoked
        TokenStore.clear()                              // refresh + access tokens
        RelayConnection.close()                         // murmur-relay WebSocket
        DeviceKeys.deleteAll()                          // DPoP key, mTLS key + cert, E2EE keys (Part IV)
        LocalDatabase.deleteAndForgetKey()              // SQLCipher DB and its Keystore-wrapped key
        WorkManager.getInstance(App.ctx).cancelAllWork()
        Navigator.showSignIn(reason)                    // "This device was signed out from Alice's Pixel"
    }
}
