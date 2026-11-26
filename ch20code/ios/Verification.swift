// Verification.swift — same states; SwiftUI renders the banner and gates the send button.
enum Trust: Equatable { case unverified, verified, changedUnverified(Date), changedFromVerified(Date) }
enum Banner { case verified, mismatch, safetyNumberChanged, blockingChanged }

final class ContactTrust: ObservableObject {
    @Published private(set) var state: Trust = .unverified
    private var aik: Data                                  // contact's AIK as last accepted
    private let qrFor: (Data) -> Data                      // expected QR payload for a given AIK
    init(aik: Data, qrFor: @escaping (Data) -> Data) { self.aik = aik; self.qrFor = qrFor }
    var canSend: Bool { if case .changedFromVerified = state { return false }; return true }

    func scanned(_ payload: Data) -> Banner {
        guard payload == qrFor(aik) else { return .mismatch }     // a wrong scan never lowers trust
        state = .verified; return .verified
    }
    func keyChanged(to newAIK: Data, at date: Date) -> Banner? {
        guard newAIK != aik else { return nil }                    // same key re-announced: no-op
        aik = newAIK                                               // future scans use the NEW key
        switch state {
        case .verified, .changedFromVerified: state = .changedFromVerified(date); return .blockingChanged
        default: state = .changedUnverified(date); return .safetyNumberChanged
        }
    }
    func acknowledged() { if case .changedUnverified = state { state = .unverified } }
}
