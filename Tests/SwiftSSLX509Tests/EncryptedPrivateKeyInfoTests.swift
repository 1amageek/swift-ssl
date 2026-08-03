import XCTest
import SwiftSSLCore
import SwiftSSLX509

final class EncryptedPrivateKeyInfoTests: XCTestCase {
    func testPBES2AES256GCMRoundTrip() throws {
        let plaintextDER = makeX25519PrivateKeyInfo()
        let password: ContiguousArray<UInt8> = [
            0x63, 0x6F, 0x72, 0x72, 0x65, 0x63, 0x74
        ]
        let profile = try makeProfile()
        let privateKeyInfo = try PrivateKeyInfo(der: plaintextDER.span)

        let encrypted = try profile.seal(
            privateKeyInfo,
            password: password.span,
            using: FixedEntropy()
        )
        XCTAssertEqual(encrypted.iterationCount, 100_000)
        XCTAssertEqual(encrypted.plaintextByteCount, plaintextDER.count)

        let reopened = try profile.open(encrypted, password: password.span)
        var reopenedDER = ContiguousArray<UInt8>()
        try reopened.withDERBytes { bytes in
            reopenedDER = copy(bytes)
        }
        XCTAssertEqual(reopenedDER, plaintextDER)
    }

    func testWrongPasswordFailsAuthentication() throws {
        let plaintextDER = makeX25519PrivateKeyInfo()
        let password: ContiguousArray<UInt8> = [0x67, 0x6F, 0x6F, 0x64]
        let wrongPassword: ContiguousArray<UInt8> = [0x62, 0x61, 0x64]
        let profile = try makeProfile()
        let privateKeyInfo = try PrivateKeyInfo(der: plaintextDER.span)
        let encrypted = try profile.seal(
            privateKeyInfo,
            password: password.span,
            using: FixedEntropy()
        )

        do {
            let reopened = try profile.open(
                encrypted,
                password: wrongPassword.span
            )
            _ = consume reopened
            XCTFail("an incorrect password authenticated")
        } catch {
            XCTAssertEqual(
                error as? PBES2AES256GCMError,
                .authenticationFailed
            )
        }
    }

    func testCiphertextModificationFailsAuthentication() throws {
        let plaintextDER = makeX25519PrivateKeyInfo()
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let profile = try makeProfile()
        let privateKeyInfo = try PrivateKeyInfo(der: plaintextDER.span)
        let encrypted = try profile.seal(
            privateKeyInfo,
            password: password.span,
            using: FixedEntropy()
        )
        var modifiedDER = encrypted.withDERBytes { bytes in
            copy(bytes)
        }
        modifiedDER[modifiedDER.count - 1] ^= 0x01
        let modified = try EncryptedPrivateKeyInfo(der: modifiedDER.span)

        do {
            let reopened = try profile.open(modified, password: password.span)
            _ = consume reopened
            XCTFail("modified ciphertext authenticated")
        } catch {
            XCTAssertEqual(
                error as? PBES2AES256GCMError,
                .authenticationFailed
            )
        }
    }

    func testRejectsUnsupportedEncryptionAlgorithm() throws {
        let plaintextDER = makeX25519PrivateKeyInfo()
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let profile = try makeProfile()
        let privateKeyInfo = try PrivateKeyInfo(der: plaintextDER.span)
        let encrypted = try profile.seal(
            privateKeyInfo,
            password: password.span,
            using: FixedEntropy()
        )
        var modifiedDER = encrypted.withDERBytes { bytes in
            copy(bytes)
        }
        let pbes2DER: [UInt8] = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x05, 0x0D,
        ]
        let oidOffset = try XCTUnwrap(firstOffset(of: pbes2DER, in: modifiedDER))
        modifiedDER[oidOffset + pbes2DER.count - 1] ^= 0x01

        do {
            _ = try EncryptedPrivateKeyInfo(der: modifiedDER.span)
            XCTFail("an unsupported encryption algorithm was accepted")
        } catch {
            XCTAssertEqual(
                error as? EncryptedPrivateKeyInfoError,
                .unsupportedEncryptionAlgorithm
            )
        }
    }

    func testRejectsIterationCountBelowPolicyBeforeDecryption() throws {
        let plaintextDER = makeX25519PrivateKeyInfo()
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let encryptionProfile = try makeProfile()
        let privateKeyInfo = try PrivateKeyInfo(der: plaintextDER.span)
        let encrypted = try encryptionProfile.seal(
            privateKeyInfo,
            password: password.span,
            using: FixedEntropy()
        )
        let stricterProfile = try PBES2AES256GCM(
            encryptionIterations: 200_000,
            minimumAcceptedIterations: 200_000,
            maximumAcceptedIterations: 1_000_000
        )

        do {
            let reopened = try stricterProfile.open(
                encrypted,
                password: password.span
            )
            _ = consume reopened
            XCTFail("an iteration count below policy was accepted")
        } catch {
            XCTAssertEqual(
                error as? PBES2AES256GCMError,
                .iterationCountOutOfPolicy(
                    minimum: 200_000,
                    maximum: 1_000_000,
                    actual: 100_000
                )
            )
        }
    }

    private func makeProfile() throws -> PBES2AES256GCM {
        try PBES2AES256GCM(
            encryptionIterations: 100_000,
            minimumAcceptedIterations: 100_000,
            maximumAcceptedIterations: 1_000_000
        )
    }

    private func makeX25519PrivateKeyInfo() -> ContiguousArray<UInt8> {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2C,
            0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x04, 0x20,
        ]
        der.append(contentsOf: repeatElement(0x5A, count: 32))
        return der
    }

    private func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }

    private func firstOffset(
        of needle: [UInt8],
        in haystack: ContiguousArray<UInt8>
    ) -> Int? {
        guard !needle.isEmpty, needle.count <= haystack.count else {
            return nil
        }
        var offset = 0
        while offset <= haystack.count - needle.count {
            var index = 0
            while index < needle.count,
                  haystack[offset + index] == needle[index] {
                index += 1
            }
            if index == needle.count {
                return offset
            }
            offset += 1
        }
        return nil
    }
}

private struct FixedEntropy: EntropySource {
    func fill(
        _ destination: inout MutableSpan<UInt8>
    ) throws(EntropyError) {
        let base: UInt8
        switch destination.count {
        case EncryptedPrivateKeyInfo.saltByteCount:
            base = 0x40
        case EncryptedPrivateKeyInfo.nonceByteCount:
            base = 0x80
        default:
            throw .requestTooLarge(limit: 16, requested: destination.count)
        }
        var index = 0
        while index < destination.count {
            destination[index] = base &+ UInt8(index)
            index += 1
        }
    }
}
