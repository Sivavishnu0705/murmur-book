// Passkeys.kt
import android.content.Context
import androidx.credentials.*
import androidx.credentials.exceptions.*

class MurmurPasskeys(private val api: MurmurAuthApi) {   // pinned, DPoP-authenticated (Ch 8, 13)

    /** Registration: run while signed in (e.g. right after sign-up, or from Settings). */
    suspend fun register(activity: Context) {
        // ① Server options: challenge, rp.id="murmur.example", user.id=random handle,
        //    residentKey=required, userVerification=required, attestation="none", excludeCredentials
        val optionsJson = api.passkeyRegistrationOptions()
        try {
            val result = CredentialManager.create(activity).createCredential(
                activity, CreatePublicKeyCredentialRequest(requestJson = optionsJson))
            val response = (result as CreatePublicKeyCredentialResponse).registrationResponseJson
            api.finishPasskeyRegistration(response)        // ② server verifies (Listing 14.3/14.4)
        } catch (e: CreateCredentialCancellationException) {
            // user dismissed: not an error
        } catch (e: CreateCredentialException) {
            // DOM errors such as InvalidStateError (already registered) or a SecurityError, which
            // almost always means assetlinks.json does not list this build's signing key.
            throw e
        }
    }

    /** Assertion: the native sign-in ceremony (used in the lab to exercise murmur-auth directly). */
    suspend fun assert(activity: Context): String {
        val optionsJson = api.passkeyAssertionOptions()     // challenge, rpId, userVerification=required
        val result = CredentialManager.create(activity).getCredential(
            activity, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson = optionsJson))))
        val cred = result.credential as? PublicKeyCredential
            ?: throw GetCredentialUnknownException("unexpected credential type")
        return cred.authenticationResponseJson              // forward unchanged; server decides
    }
}
