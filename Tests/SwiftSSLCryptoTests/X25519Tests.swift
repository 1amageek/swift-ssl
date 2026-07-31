import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class X25519Tests: XCTestCase {
    func testRFC7748AlicePublicKey() throws {
        let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let expectedPublic = bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let privateKey = try X25519PrivateKey(bytes: privateBytes.span)

        let publicKey = privateKey.publicKey()
        XCTAssertEqual(copyBytes(publicKey.span), Array(expectedPublic))
    }

    func testSharedSecretMatchesIndependentImplementationVector() throws {
        let alicePrivate = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPrivate = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let expected = bytes("5bf220d670c94b8d70bc5ede1cffb85d6c4b7c9d8717bbb5eb90c02583862007")

        let alice = try X25519PrivateKey(bytes: alicePrivate.span)
        let bob = try X25519PrivateKey(bytes: bobPrivate.span)
        let shared = try X25519.sharedSecret(privateKey: alice, peerPublicKey: bob.publicKey())
        let actual = shared.withBorrowedBytes { copyBytes($0) }

        XCTAssertEqual(actual, Array(expected))
    }

    func testDeterministicFieldVectors() throws {
        let vectors = [
            (
                "071a2d405366798c9fb2c5d8ebfe1124374a5d708396a9bccfe2f5081b2e4154",
                "032241607f9ebddcfb1a39587796b5d4f31231506f8eadcceb0a29486786a5c4",
                "58d384f9f6b902c06240510fdf10381db63fe85aa32242a35bf975b5e1ecf03d",
                "dd2ca84fb07a5772486d7a1bf155a1b0063817b6c95f5c59b0d6f2508f071464"
            ),
            (
                "2c3f5265788b9eb1c4d7eafd102336495c6f8295a8bbcee1f4071a2d40536679",
                "0e2d4c6b8aa9c8e70625446382a1c0dffe1d3c5b7a99b8d7f61534537291b0cf",
                "5e0218a005e76a0348e99aac665ebbfcb8eb2ba185079c3c8cab5ccb6cb9cb7a",
                "238d0222c48417aabb07e53ffd411f8bc310802c16858fd1fd070491f3bba562"
            ),
            (
                "5164778a9db0c3d6e9fc0f2235485b6e8194a7bacde0f306192c3f5265788b9e",
                "1938577695b4d3f211304f6e8daccbea0928476685a4c3e201203f5e7d9cbbda",
                "fd134960e08c49fddbc1eb5f793d34c86384eb0e2bfb411309e89ce0ccbca158",
                "dfb60cfd3cea9499c2d0c549996773dfe385e0e6bb73c4fc9fbd521e2e003227"
            ),
            (
                "76899cafc2d5e8fb0e2134475a6d8093a6b9ccdff205182b3e5164778a9db0c3",
                "24436281a0bfdefd1c3b5a7998b7d6f51433527190afceed0c2b4a6988a7c6e5",
                "ed80eabffad44b099c3c9c62d76b1ba3d78b9742c6122060e3f51ecda400a476",
                "5a34659400af7b6267bc4d4b0fa17b38bb41f37eb83a1edc5989af30f452154e"
            )
        ]

        for (aliceHex, bobHex, publicHex, sharedHex) in vectors {
            let aliceBytes = bytes(aliceHex)
            let bobBytes = bytes(bobHex)
            let alice = try X25519PrivateKey(bytes: aliceBytes.span)
            let bob = try X25519PrivateKey(bytes: bobBytes.span)

            XCTAssertEqual(copyBytes(alice.publicKey().span), Array(bytes(publicHex)))
            let shared = try X25519.sharedSecret(privateKey: alice, peerPublicKey: bob.publicKey())
            XCTAssertEqual(shared.withBorrowedBytes { copyBytes($0) }, Array(bytes(sharedHex)))
        }
    }

    func testAllZeroPeerKeyIsRejectedWithoutReturningSecret() throws {
        let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let zeroPeer = ContiguousArray<UInt8>(repeating: 0, count: X25519PublicKey.byteCount)
        let privateKey = try X25519PrivateKey(bytes: privateBytes.span)
        let peer = try X25519PublicKey(bytes: zeroPeer.span)

        do {
            let unused = try X25519.sharedSecret(privateKey: privateKey, peerPublicKey: peer)
            _ = unused
            XCTFail("all-zero peer key was accepted")
        } catch {
            XCTAssertEqual(error, .invalidPeerKey)
        }
    }

    func testKeyLengthValidation() {
        let invalid = ContiguousArray<UInt8>(repeating: 0, count: 31)
        do {
            let unused = try X25519PrivateKey(bytes: invalid.span)
            _ = unused
            XCTFail("invalid private-key length was accepted")
        } catch {
            XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
        }
        do {
            let unused = try X25519PublicKey(bytes: invalid.span)
            _ = unused
            XCTFail("invalid public-key length was accepted")
        } catch {
            XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
        }
    }

    private func copyBytes(_ bytes: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<next], radix: 16)!)
            index = next
        }
        return result
    }
}
