// Uses the UniFFI-generated module murmur_mls.
import Foundation

final class GroupSession {
    private let mls: MurmurMls
    private let ds: DeliveryService
    init(identity: Data,
        ds: DeliveryService) throws { mls = try MurmurMls(identity: identity);
        self.ds = ds }

    func onIncoming(_ wire: Data) throws -> String? {
        switch try mls.process(wire: wire) {
        case .application(let sender, let plaintext):
            return "\(String(decoding: sender, as: UTF8.self)): " +
                "\(String(decoding: plaintext, as: UTF8.self))"
        case .commitMerged(let epoch):
            NotificationCenter.default.post(name: .groupChanged,
                object: epoch); return nil
        case .other:
            return nil
        }
    }

    // PCS discipline (§23.7)
    func periodicUpdate(groupId: Data) async throws {
        let out = try mls.selfUpdate()
        if try await ds.submitCommit(groupId: groupId,
            commit: out.commit) == .accepted {
            _ = try mls.mergePending()
        } else {
            // lost the race; try again later
            try mls.clearPending()
        }
    }
}
