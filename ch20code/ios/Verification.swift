// Verification.swift — same states; SwiftUI renders the banner and gates the
// send button.
enum Trust: Equatable { case unverified, verified, changedUnverified(Date),
    changedFromVerified(Date) }
enum Banner { case verified, mismatch, safetyNumberChanged, blockingChanged }

final class ContactTrust: ObservableObject {
    @Published private(set) var state: Trust = .unverified
    // contact's AIK as last accepted
    private var aik: Data
    // expected QR payload for a given AIK
    private let qrFor: (Data) -> Data
    init(aik: Data, qrFor: @escaping (Data) -> Data) { self.aik = aik;
        self.qrFor = qrFor }
    var canSend: Bool { if case .changedFromVerified = state { return false };
        return true }

    func scanned(_ payload: Data) -> Banner {
        // a wrong scan never lowers trust
        guard payload == qrFor(aik) else { return .mismatch }
        state = .verified; return .verified
    }
    func keyChanged(to newAIK: Data, at date: Date) -> Banner? {
        // same key re-announced: no-op
        guard newAIK != aik else { return nil }
        // future scans use the NEW key
        aik = newAIK
        switch state {
        case .verified,
            .changedFromVerified: state = .changedFromVerified(
            date); return .blockingChanged
        default: state = .changedUnverified(date); return .safetyNumberChanged
        }
    }
    func acknowledged() { if case .changedUnverified = state {
        state = .unverified } }
}
