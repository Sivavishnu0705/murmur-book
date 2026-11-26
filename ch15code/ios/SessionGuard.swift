// SessionGuard.swift — same policy on iOS. Background pushes are throttled and may not arrive,
// so the check also runs at launch, on foreground, and after unrecoverable 401s.
import UIKit

final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ app: UIApplication, didReceiveRemoteNotification info: [AnyHashable: Any],
                     fetchCompletionHandler done: @escaping (UIBackgroundFetchResult) -> Void) {
        guard info["type"] as? String == "session_revoked" else { return done(.noData) }
        Task {
            switch await Session.shared.verifiedStatus() {     // GET /v1/session, pinned + DPoP
            case .revoked: await Session.shared.forceSignOut(reason: .remote); done(.newData)
            case .active:  done(.noData)                       // spurious or forged hint: ignore
            case .unreachable: done(.failed)                   // try again on next launch/foreground
            }
        }
    }
}

actor Session {
    static let shared = Session()
    func verifiedStatus() async -> SessionStatus { await MurmurAPI.shared.sessionStatus() }

    func handle401(wwwAuthenticate: String, refreshError: String?) async -> AuthAction {
        if wwwAuthenticate.contains("insufficient_user_authentication") { return .stepUp }
        if wwwAuthenticate.contains("use_dpop_nonce") { return .retryWithNonce }
        if refreshError == "attestation_required" { return .showDeviceIntegrity }
        if refreshError == "invalid_grant" { await forceSignOut(reason: .expired); return .signedOut }
        return .refreshOnce
    }

    func forceSignOut(reason: SignOutReason) async {
        try? await MurmurAPI.shared.revokeRefreshToken()       // best-effort
        TokenStore.clear()                                     // Keychain items in the shared group,
        DeviceKeys.deleteAll()                                 // so the NSE loses access too
        await RelayConnection.shared.close()
        LocalDatabase.deleteAndForgetKey()
        await MainActor.run { AppRouter.shared.showSignIn(reason: reason) }
    }
}
