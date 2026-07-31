import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class Ed25519Tests: XCTestCase {
    func testRFC8032SigningVector() throws {
        let seed = bytes(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        let expectedPublicKey = bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        let expectedSignature = bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        let privateKey = try Ed25519PrivateKey(seed: seed.span)
        let publicKey = try privateKey.publicKey()
        let signature = try privateKey.sign(message: ContiguousArray<UInt8>().span)

        XCTAssertEqual(publicKey, expectedPublicKey)
        XCTAssertEqual(signature, expectedSignature)
    }

    func testRFC8032EmptyMessageVector() throws {
        let publicKey = bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        let signature = bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        let valid = try Ed25519.verify(
            signature: signature.span,
            message: ContiguousArray<UInt8>().span,
            publicKey: publicKey.span
        )

        XCTAssertTrue(valid)
    }

    func testModifiedMessageDoesNotVerify() throws {
        let publicKey = bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        let signature = bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        let message = ContiguousArray<UInt8>([0])

        let valid = try Ed25519.verify(
            signature: signature.span,
            message: message.span,
            publicKey: publicKey.span
        )

        XCTAssertFalse(valid)
    }

    func testNonCanonicalScalarIsRejected() throws {
        let publicKey = bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        var signature = bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        signature.replaceSubrange(32..<64, with: bytes(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        ))

        do {
            let unused = try Ed25519.verify(
                signature: signature.span,
                message: ContiguousArray<UInt8>().span,
                publicKey: publicKey.span
            )
            _ = unused
            XCTFail("non-canonical scalar was accepted")
        } catch {
            XCTAssertEqual(error as? CryptoInputError, .nonCanonicalEncoding)
        }
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
