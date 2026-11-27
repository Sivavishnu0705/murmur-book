import CryptoKit
import Foundation

/// Derives a 32-byte ChaChaPoly key from an X25519 agreement.
/// Salt binds both public keys; info is a Murmur label (domain separation).
func deriveKey(mine: Curve25519.KeyAgreement.PrivateKey,
               theirs: Curve25519.KeyAgreement.PublicKey,
               initiatorPub: Data, responderPub: Data) throws -> SymmetricKey {
    let shared = try mine.sharedSecretFromKeyAgreement(with: theirs)

    // Defense in depth: refuse an all-zero shared secret (low-order peer key).
    let isAllZero = shared.withUnsafeBytes { $0.allSatisfy { $0 == 0 } }
    guard !isAllZero else { throw CryptoKitError.incorrectParameterSize }

    return shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: initiatorPub + responderPub,
        sharedInfo: Data("murmur/v1/ch02/demo".utf8),
        outputByteCount: 32)
}

func demo() throws {
    let alice = Curve25519.KeyAgreement.PrivateKey()
    let bob   = Curve25519.KeyAgreement.PrivateKey()
    let aPub  = alice.publicKey.rawRepresentation          // 32 bytes
    let bPub  = bob.publicKey.rawRepresentation            // 32 bytes

    // Alice encrypts. The header travels in the clear but is authenticated.
    let header = Data(#"{"v":1,"from":"alice","to":"bob"}"#.utf8)
    let aliceKey = try deriveKey(mine: alice, theirs: bob.publicKey,
                                 initiatorPub: aPub, responderPub: bPub)
    let sealed = try ChaChaPoly.seal(Data("Are you free at 7?".utf8),
                                     using: aliceKey,
                                     authenticating: header)   // random nonce
    let wire = sealed.combined          // nonce (12) ‖ ciphertext ‖ tag (16)

    // Bob derives the same key from his side and opens.
    let bobKey = try deriveKey(mine: bob, theirs: alice.publicKey,
                               initiatorPub: aPub, responderPub: bPub)
    let box = try ChaChaPoly.SealedBox(combined: wire)
    let plaintext = try ChaChaPoly.open(box, using: bobKey,
        authenticating: header)
    print(String(decoding: plaintext, as: UTF8.self))   // "Are you free at 7?"
}
