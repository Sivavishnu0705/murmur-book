// X3DH.swift — matches x3dh_vectors.json. CryptoKit's Curve25519 and HKDF.
import CryptoKit
import Foundation

enum X3DH {
    static let info = Data("Murmur_X3DH_v1".utf8)
    static let F = Data(repeating: 0xFF, count: 32)
    static func encode(_ pub: Data) -> Data { Data([0x05]) + pub }

    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: Data) throws -> Data {
        let shared = try priv.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub))
        let bytes = shared.withUnsafeBytes { Data($0) }
        guard bytes.contains(where: { $0 != 0 }) else { throw X3DHError.lowOrderKey }
        return bytes
    }

    static func initiate(ikA: Curve25519.KeyAgreement.PrivateKey, ekA: Curve25519.KeyAgreement.PrivateKey,
                         bundle b: Bundle) throws -> (sk: SymmetricKey, ad: Data) {
        guard MurmurCore.verifyXeddsa(identity: b.ik, message: encode(b.spk), signature: b.spkSig)
        else { throw X3DHError.badSignature }
        var km = try dh(ikA, b.spk) + dh(ekA, b.ik) + dh(ekA, b.spk)       // DH1 ‖ DH2 ‖ DH3
        if let opk = b.opk { km += try dh(ekA, opk) }                       // ‖ DH4
        let sk = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: F + km),
                                        salt: Data(count: 32), info: info, outputByteCount: 32)
        return (sk, encode(ikA.publicKey.rawRepresentation) + encode(b.ik))
    }
}
enum X3DHError: Error { case badSignature, lowOrderKey }

// XCTest: decode x3dh_vectors.json; construct keys with
// Curve25519.KeyAgreement.PrivateKey(rawRepresentation:); assert the derived key's bytes == sk.
