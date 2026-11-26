// PrekeyTask.swift
// Listing 28.10 — Swift: BGTaskScheduler prekey job. iOS decides when a refresh task runs (often
// overnight, on power and Wi-Fi), so the app ALSO runs maintenance on every foreground launch
// and after any fetch that reports low stock. Info.plist lists the identifier under
// BGTaskSchedulerPermittedIdentifiers.
import BackgroundTasks
import Foundation
import MurmurCore

enum PrekeyTask {
    static let identifier = "example.murmur.prekeys"

    /// Call from application(_:didFinishLaunchingWithOptions:), before the launch completes.
    static func register(app: MurmurApp) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            handle(task as! BGAppRefreshTask, app: app)
        }
    }

    static func schedule() {
        let req = BGAppRefreshTaskRequest(identifier: identifier)
        req.earliestBeginDate = Date(timeIntervalSinceNow: 12 * 3600)
        try? BGTaskScheduler.shared.submit(req)          // replaces any pending request
    }

    private static func handle(_ task: BGAppRefreshTask, app: MurmurApp) {
        schedule()                                       // always queue the next one first
        let work = Task {
            do {
                guard app.session.isEnrolled else { return task.setTaskCompleted(success: true) }
                let report = try await app.core.maintainPrekeys(api: app.api, now: UInt64(Date().timeIntervalSince1970))
                app.securityLog.record("prekeys", report.summary)
                task.setTaskCompleted(success: true)
            } catch CoreError.KeyUnavailable {
                app.session.onKeysLost()                 // SE key gone (device restored, etc.): re-enroll
                task.setTaskCompleted(success: false)
            } catch {
                task.setTaskCompleted(success: false)    // network: the next run or launch retries
            }
        }
        task.expirationHandler = { work.cancel() }       // iOS is out of patience: stop cleanly
    }
}
