import XCTest
import CryptoKit

final class EnvelopeVectorTests: XCTestCase {
    func hex(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            let i = s.index(s.startIndex, offsetBy: $0)
            return UInt8(s[i..<s.index(i, offsetBy: 2)], radix: 16)!
        })
    }

    func testMatchesPythonVector() throws {
        let r = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation:
            hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let e = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation:
            hex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        let expected = hex(
            "01de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b" +
            "4f" +
            "edb334937ff8c4094bce55fdb553e8ac164a19e8175802b7c4c44e7b3aa42b00" +
            "0eef")
        let sealed = try MurmurEnvelope.seal(Data("Are you free at 7?".utf8),
                                             to: r.publicKey, ephemeral: e)
        XCTAssertEqual(sealed, expected)
        XCTAssertEqual(try MurmurEnvelope.openEnvelope(expected, with: r),
                       Data("Are you free at 7?".utf8))
    }
}
