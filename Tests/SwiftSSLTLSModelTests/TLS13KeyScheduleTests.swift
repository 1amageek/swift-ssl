import XCTest
import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

final class TLS13KeyScheduleTests: XCTestCase {
    func testDerivesHandshakeAndApplicationTrafficSecrets() throws {
        let emptyPSK = ContiguousArray<UInt8>()
        let ecdhe = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
        let transcript = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
        var schedule = try TLS13KeySchedule(
            cipherSuite: .aes128GCM_SHA256,
            preSharedKey: emptyPSK.span
        )
        let handshake = try schedule.makeHandshakeSecrets(
            ecdheSharedSecret: ecdhe.span,
            transcriptHash: transcript.span
        )
        var clientSecret = ContiguousArray<UInt8>()
        try handshake.withClientTrafficSecret { secret in
            clientSecret = copy(secret)
        }
        XCTAssertEqual(clientSecret.count, 32)
        XCTAssertNotEqual(Set(clientSecret), [0])

        let serverFinished = try handshake.makeServerFinishedVerifyData(
            transcriptHash: transcript.span
        )
        XCTAssertEqual(serverFinished.count, 32)
        XCTAssertNotEqual(copy(serverFinished.span), clientSecret)

        let application = try handshake.makeApplicationSecrets(transcriptHash: transcript.span)
        var applicationSecret = ContiguousArray<UInt8>()
        try application.withServerTrafficSecret { secret in
            applicationSecret = copy(secret)
        }
        XCTAssertEqual(applicationSecret.count, 32)
        XCTAssertNotEqual(applicationSecret, clientSecret)
    }

    func testSHA384SuiteAndInputFailures() throws {
        let psk = ContiguousArray<UInt8>(repeating: 0x55, count: 48)
        let ecdhe = ContiguousArray<UInt8>(repeating: 0x66, count: X25519SharedSecret.byteCount)
        let transcript = ContiguousArray<UInt8>(repeating: 0x77, count: 48)
        let schedule = try TLS13KeySchedule(
            cipherSuite: .aes256GCM_SHA384,
            preSharedKey: psk.span
        )
        let handshake = try schedule.makeHandshakeSecrets(
            ecdheSharedSecret: ecdhe.span,
            transcriptHash: transcript.span
        )
        try handshake.withServerTrafficSecret { secret in
            XCTAssertEqual(secret.count, 48)
        }

        let invalidECDHE = ContiguousArray<UInt8>(repeating: 0, count: 48)
        do {
            _ = try schedule.makeHandshakeSecrets(
                ecdheSharedSecret: invalidECDHE.span,
                transcriptHash: transcript.span
            )
            XCTFail("invalid ECDHE length was accepted")
        } catch {
            XCTAssertEqual(error as? TLS13KeyScheduleError, .invalidECDHESecretLength(actual: 48))
        }
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
}
