// NotificationService.swift — the push carries only
// {"aps":{"alert":{"title":"Murmur", "body":"New
// message"},"mutable-content":1},"v":1}. Everything else is fetched and
// decrypted here.
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var fallback: UNMutableNotificationContent?
    private var task: Task<Void, Never>?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (
                             UNNotificationContent) -> Void) {
        handler = contentHandler
        let content = (
            request.content.mutableCopy() as? UNMutableNotificationContent) ??
            UNMutableNotificationContent()
        // "New message": shown if we run out of time
        fallback = content

        task = Task {
            do {
                // Shared state: App Group SQLCipher DB + Keychain access group
                // (Ch 19 §19.9, §29.5).
                let core = try MurmurCore.openShared(
                    appGroup: "group.example.murmur",
                    keychainGroup: "ABCDE12345.example.murmur.shared")
                // Pinned TLS + DPoP (Secure Enclave key in the shared Keychain
                // group).
                let envelopes = try await core.relay.fetchQueued(limit: 5)
                var latest: DecryptedMessage?
                for env in envelopes {
                    // unseal → verify sender cert → Double Ratchet decrypt,
                    // inside BEGIN IMMEDIATE; acknowledges to the relay only
                    // after COMMIT.
                    if let m = try core.receive(envelope: env) { latest = m }
                }
                guard let m = latest,
                    !Task.isCancelled else { return self.finish(content) }
                // composed locally, never sent to Apple
                content.title = m.senderDisplayName
                content.body = m.previewsEnabled ? m.previewText : "New message"
                // groups notifications on device
                content.threadIdentifier = m.conversationID
                self.finish(content)
            } catch {
                // never crash; show the placeholder
                self.finish(content)
            }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        // stop BEFORE iOS kills us mid-transaction
        task?.cancel()
        if let fallback { finish(fallback) }
    }

    private func finish(_ c: UNNotificationContent) {
        guard let h = handler else { return }
        handler = nil
        h(c)
    }
}
