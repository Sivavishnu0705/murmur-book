// GoogleSignIn.kt — Credential Manager + Sign in with Google, backend-issued
// nonce.
import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential

class GoogleSignIn(private val ctx: Context, private val auth: MurmurAuthApi) {
    // The server (web) client ID: it becomes the ID token's `aud`. Not a
    // secret.
    private val serverClientId = "123456789012-web.apps.googleusercontent.com"

    suspend fun signIn(activityContext: Context): MurmurTokens {
        // ① issued and stored by murmur-auth
        val nonce = auth.newLoginNonce()
        val option = GetGoogleIdOption.Builder()
            .setServerClientId(serverClientId)
            .setFilterByAuthorizedAccounts(false)
            // ② carried into the ID token
            .setNonce(nonce)
            .build()
        val result = CredentialManager.create(ctx).getCredential(
            activityContext,
            GetCredentialRequest.Builder().addCredentialOption(option).build())
        val cred = result.credential
        require(cred is CustomCredential &&
                cred.type ==
                GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL)
        val idToken = GoogleIdTokenCredential.createFrom(cred.data).idToken
        // ③ Send the TOKEN, not claims, over the pinned connection (Ch 8).
        // Never parse it to decide who the user is: the backend's validation is
        // the only one that counts.
        return auth.federate(provider = "google", idToken = idToken,
            nonce = nonce)
    }
}
