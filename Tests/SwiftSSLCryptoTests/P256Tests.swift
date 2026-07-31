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
        let product = (x * x).encoded
        let expectedProduct = bytes("98F6B84D29BEF2B281819A5E0E3690D833B699495D694DD1002AE56C426B3F8C")
        XCTAssertEqual(product, expectedProduct)
        let inverse = x.inverted().encoded
        let expectedInverse = bytes("E060CBB088706D5D24936933B69B16AB707D656273744B65664C49E577F35238")
        XCTAssertEqual(inverse, expectedInverse)
        let identity = (x * x.inverted()).encoded
        XCTAssertEqual(identity, P256Field.one.encoded)
    }

    func testGeneratorAndDeterministicPublicKey() throws {
        let scalar = bytes("0000000000000000000000000000000000000000000000000000000000000001")
        let key = try P256PrivateKey(bytes: scalar.span)
        let expected = bytes(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        XCTAssertEqual(copyBytes(key.publicKey().span), Array(expected))

        let two = bytes("0000000000000000000000000000000000000000000000000000000000000002")
        let twoKey = try P256PrivateKey(bytes: two.span)
        let expectedTwo = bytes(
            "047CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978" +
            "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"
        )
        XCTAssertEqual(copyBytes(twoKey.publicKey().span), Array(expectedTwo))
    }

    func testDeterministicECDHMatchesIndependentVector() throws {
        let aliceScalar = bytes(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
        )
        let bobScalar = bytes(
            "A6E3C57DD01ABE90086538398355DD4C3B17AA2A3B8A9A2A1455D75FBA5C7B1D"
        )
        let expectedAlicePublic = bytes(
            "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
        )
        let expectedShared = bytes(
            "DF4237B90A9EF5BFF082378625C16FEB97D8B18F59CEB7BF6B18E721DFF93B93"
        )
        let alice = try P256PrivateKey(bytes: aliceScalar.span)
        let bob = try P256PrivateKey(bytes: bobScalar.span)
        XCTAssertEqual(copyBytes(alice.publicKey().span), Array(expectedAlicePublic))

        let aliceSecret = try P256.sharedSecret(
            privateKey: alice,
            peerPublicKey: bob.publicKey()
        )
        let bobSecret = try P256.sharedSecret(
            privateKey: bob,
            peerPublicKey: alice.publicKey()
        )
        XCTAssertEqual(aliceSecret.withBorrowedBytes { copyBytes($0) }, Array(expectedShared))
        XCTAssertEqual(bobSecret.withBorrowedBytes { copyBytes($0) }, Array(expectedShared))
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
            publicKey: key
        ))

        var mutated = rawSignature
        mutated[63] ^= 1
        XCTAssertFalse(try P256ECDSA.verify(
            signature: mutated.span,
            messageHash: digest.span,
            publicKey: key
        ))
    }

    func testECDSASigningUsesRFC6979VectorAndRoundTrips() throws {
        let privateBytes = bytes(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
        )
        let digest = bytes(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF"
        )
        let expected = bytes(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716" +
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
        )
        let key = try P256PrivateKey(bytes: privateBytes.span)
        let signature = try P256ECDSA.sign(
            messageHash: digest.span,
            privateKey: key
        )
        XCTAssertEqual(signature, expected)
        XCTAssertTrue(try P256ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: key.publicKey()
        ))
    }

    func testRejectsInvalidScalarAndPoint() throws {
        let zero = ContiguousArray<UInt8>(repeating: 0, count: P256PrivateKey.byteCount)
        do {
            let unused = try P256PrivateKey(bytes: zero.span)
            _ = unused
            XCTFail("zero scalar was accepted")
        } catch {
            XCTAssertEqual(error as? CryptoInputError, .nonCanonicalEncoding)
        }

        let order = bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        do {
            let unused = try P256PrivateKey(bytes: order.span)
            _ = unused
            XCTFail("order scalar was accepted")
        } catch {
            XCTAssertEqual(error as? CryptoInputError, .nonCanonicalEncoding)
        }

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

    func testKeyGenerationRejectsInvalidEntropyAfterBoundedRetries() {
        let entropy = FixedEntropy(bytes: ContiguousArray(repeating: 0, count: 32))
        do {
            let unused = try P256PrivateKey.generate(using: entropy)
            _ = unused
            XCTFail("invalid entropy produced a scalar")
        } catch {
            XCTAssertEqual(error, .invalidScalar)
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

    private struct FixedEntropy: EntropySource {
        let bytes: ContiguousArray<UInt8>

        func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
            guard destination.count == bytes.count else {
                throw .partialFill(expected: destination.count, actual: bytes.count)
            }
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }
}
