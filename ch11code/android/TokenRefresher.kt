// TokenRefresher.kt — single-flight refresh with coroutines, plus an OkHttp Authenticator.
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

data class Tokens(val accessToken: String, val refreshToken: String)

interface TokenStore { fun load(): Tokens?; fun save(t: Tokens); fun clear() }
interface AuthApi { suspend fun refresh(refreshToken: String): Tokens }   // throws on invalid_grant

class TokenRefresher(private val api: AuthApi, private val store: TokenStore,
                     private val scope: CoroutineScope) {
    private val mutex = Mutex()
    private var inflight: Deferred<Tokens>? = null

    /** Returns valid tokens. `failedAccessToken` is the token that just got a 401. */
    suspend fun refreshAfter(failedAccessToken: String): Tokens {
        val job = mutex.withLock {
            val current = store.load() ?: throw IllegalStateException("signed out")
            // Someone already refreshed since this request was sent: just use the new token.
            if (current.accessToken != failedAccessToken) return current
            inflight ?: scope.async {
                try {
                    api.refresh(current.refreshToken).also { store.save(it) }  // persist rotation FIRST
                } catch (e: Exception) {
                    store.clear()                                              // invalid_grant → sign out
                    throw e
                } finally {
                    mutex.withLock { inflight = null }
                }
            }.also { inflight = it }
        }
        return job.await()                                                     // all callers share one result
    }
}

/** OkHttp calls this on a 401. It runs on a network thread, so blocking here is acceptable. */
class MurmurAuthenticator(private val refresher: TokenRefresher) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        if (response.priorResponse != null) return null                       // already retried once
        val failed = response.request.header("Authorization")?.removePrefix("Bearer ") ?: return null
        val fresh = runCatching { runBlocking { refresher.refreshAfter(failed) } }.getOrNull() ?: return null
        return response.request.newBuilder().header("Authorization", "Bearer ${fresh.accessToken}").build()
    }
}
