// NotificationService.swift
// Listing 29.9 — Swift: the Notification Service Extension. It opens the SAME SQLCipher database
// as the app (App Group container, key from the shared Keychain access group), decrypts inside
// the core's IMMEDIATE transaction, closes the database BEFORE handing the notification back
// (a process suspended while holding a lock in a shared container is killed: 0xdead10cc), tells
// the app to reload with a Darwin notification, and stays inside its ~24 MB memory budget.
import Foundation
import MurmurCore
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var best: UNMutableNotificationContent?
    private var work: Task<Void, Never>?
    private var core: MurmurCore?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        // The push carried only {"aps":{"alert":{"title":"Murmur","body":"New message"},…},"v":1}.
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        best = content
        work = Task {
            defer { self.finish() }
            do {
                // 1. Key from the shared Keychain. Before the first unlock after boot this throws
                //    errSecInteractionNotAllowed: keep the generic placeholder and stop.
                let keyAndSalt = try DatabaseKey.load()
                let core = try MurmurCore.open(dbPath: MurmurStorage.directory.appendingPathComponent("core.db").path,
                                               dbKey: keyAndSalt, wrap: SecureEnclaveKeyWrap())
                self.core = core
                let api = MurmurAPIClient(tokens: SharedTokens(core: core), pinning: PinningDelegate(AppPins.all))   // the app's pin set (Ch 8)
                let pipeline = MessagePipeline(core: core, api: api, events: NoUIEvents())
                // 2. A small batch only: the NSE has ~30 s and ~24 MB. The app takes the rest.
                let results = try await pipeline.receive(budget: 10)
                // 3. Show content ONLY after it decrypted locally. Previews are a user setting.
                if case let .message(sender, text, _)? = results.last(where: { if case .message = $0 { return true }; return false }) {
                    content.title = Contacts.displayName(sender)          // from app.db, also in the App Group
                    content.body = Preferences.showPreviews ? text : "New message"
                    content.threadIdentifier = sender
                }
                if results.contains(where: { if case .message = $0 { return true }; return false }) {
                    content.badge = NSNumber(value: try core.unreadCount())
                }
            } catch {
                // Locked before first unlock, network down, budget exceeded: the placeholder stands,
                // nothing was acknowledged that was not committed, and the app will catch up.
            }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        work?.cancel()                                     // stop between envelopes, not mid-transaction
        finish()
    }

    private func finish() {
        guard let handler = handler else { return }
        self.handler = nil
        core?.closeDatabase()                              // releases every SQLite/SQLCipher lock NOW
        core = nil
        // Tell a running app to reload its view of the database (no payload: just "something changed").
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName("example.murmur.db-changed" as CFString), nil, nil, true)
        handler(best ?? UNNotificationContent())
    }
}
