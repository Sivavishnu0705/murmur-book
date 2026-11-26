import CryptoKit
import Foundation

enum EnvelopeError: Error { case malformed, lowOrderPoint }

enum MurmurEnvelope {
    static let version: UInt8 = 0x01
    static let info = Data("murmur/v1/ch02/envelope".utf8)

    private static func derive(_ shared: SharedSecret, E: Data, R: Data)
        throws -> (SymmetricKey, ChaChaPoly.Nonce) {
        let ikm = shared.withUnsafeBytes { Data($0) }
        guard ikm.contains(where: { $0 != 0 }) else { throw EnvelopeError.lowOrderPoint }
        let okm = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                                         salt: E + R, info: info, outputByteCount: 44)
        let bytes = okm.withUnsafeBytes { Data($0) }
        return (SymmetricKey(data: bytes.prefix(32)),
                try ChaChaPoly.Nonce(data: bytes.suffix(12)))
    }

    /// `ephemeral` is for test vectors ONLY. Production callers omit it.
    static func seal(_ plaintext: Data,
                     to recipient: Curve25519.KeyAgreement.PublicKey,
                     ephemeral: Curve25519.KeyAgreement.PrivateKey = .init()) throws -> Data {
        let E = ephemeral.publicKey.rawRepresentation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let (key, nonce) = try derive(shared, E: E, R: recipient.rawRepresentation)
        let aad = Data([version]) + E
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        return aad + box.ciphertext + box.tag
    }

    static func openEnvelope(_ envelope: Data,
                             with recipient: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        let env = Data(envelope)                          // normalize indices to start at 0
        guard env.count >= 1 + 32 + 16, env[0] == version else { throw EnvelopeError.malformed }
        let E = env.subdata(in: 1..<33)
        let body = env.subdata(in: 33..<env.count)
        let ephemeralPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: E)
        let shared = try recipient.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let (key, nonce) = try derive(shared, E: E, R: recipient.publicKey.rawRepresentation)
        let box = try ChaChaPoly.SealedBox(nonce: nonce,
                                           ciphertext: body.dropLast(16),
                                           tag: body.suffix(16))
        return try ChaChaPoly.open(box, using: key, authenticating: Data([version]) + E)
    }
}
