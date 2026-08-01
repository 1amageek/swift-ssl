import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class P256Tests: XCTestCase {
    func testFieldMultiplicationAndInversion() {
        let x = P256Field(hex: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
        XCTAssertEqual(x.encoded, bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"))
        XCTAssertEqual(
            P256Field(words: P256Field.modulus).encoded,
            bytes("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
        )
        XCTAssertEqual(
            (x * x).encoded,
            bytes("98F6B84D29BEF2B281819A5E0E3690D833B699495D694DD1002AE56C426B3F8C")
        )
        XCTAssertEqual(
            x.inverted().encoded,
            bytes("E060CBB088706D5D24936933B69B16AB707D656273744B65664C49E577F35238")
        )
        XCTAssertEqual((x * x.inverted()).encoded, P256Field.one.encoded)
    }

    func testECDSAVerificationMatchesIndependentVectorAndRejectsMutation() throws {
        let publicKey = bytes(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        let digest = bytes("172B1296FEDDD5E2C0B6300615142D3C4F6D375E5CB70ED8CFA9220CCEB94BE2")
        let rawSignature = bytes(
            "B186796906E26621D8940DDDF79330F38FB9EB6D8D8D88236E7223C71119C8CE" +
            "FA037545B606E053DBFB53AFF1D182250E1CD6BEF8EF5B6F56C35C0B3EE8AF64"
        )
        let key = try P256PublicKey(bytes: publicKey.span)
        XCTAssertTrue(try P256ECDSA.verify(
            signature: rawSignature.span,
            messageHash: digest.span,
            using: key
        ))

        var mutated = rawSignature
        mutated[63] ^= 1
        XCTAssertFalse(try P256ECDSA.verify(
            signature: mutated.span,
            messageHash: digest.span,
            using: key
        ))
    }

    func testRejectsInvalidPublicPoints() {
        var invalid = ContiguousArray<UInt8>(repeating: 0, count: P256PublicKey.uncompressedByteCount)
        invalid[0] = 0x04
        invalid[32] = 1
        invalid[64] = 1
        XCTAssertThrowsError(try P256PublicKey(bytes: invalid.span)) { error in
            XCTAssertEqual(error as? CryptoInputError, .invalidPeerKey)
        }

        let nonCanonicalX = bytes(
            "04FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        XCTAssertThrowsError(try P256PublicKey(bytes: nonCanonicalX.span)) { error in
            XCTAssertEqual(error as? CryptoInputError, .invalidPeerKey)
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
