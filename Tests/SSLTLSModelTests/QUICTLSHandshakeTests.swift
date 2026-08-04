import SSLCore
import SSLCrypto
import SSLTLS
import SSLX509
import XCTest

@testable import SSLQUIC

/// Verifies the complete-message boundary between QUIC transport ownership and
/// the SSLQUIC TLS mechanism. CRYPTO offsets and reassembly are intentionally
/// not represented in this target; the transport supplies one TLS message at a
/// time through `processHandshakeMessage`.
final class QUICTLSHandshakeTests: XCTestCase {
    func testCompleteMessageHandshakeCompletes() throws {
        var endpoints = try makeEndpoints()

        let clientStart = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(
            clientStart.emissions.first(where: { $0.level == .initial })
        )
        var serverFlight = Snapshot()
        for message in completeMessages(from: clientHello.bytes) {
            let output = try snapshot(
                endpoints.server.processHandshakeMessage(
                    message.span,
                    at: .initial
                )
            )
            serverFlight.emissions.append(contentsOf: output.emissions)
            serverFlight.completed = serverFlight.completed || output.completed
            serverFlight.confirmed = serverFlight.confirmed || output.confirmed
        }

        let serverHello = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .initial })
        )
        let serverHandshake = serverFlight.emissions.filter {
            $0.level == .handshake
        }
        _ = try snapshot(
            endpoints.client.processHandshakeMessage(
                serverHello.bytes.span,
                at: .initial
            )
        )

        var clientFlight = Snapshot()
        for emission in serverHandshake {
            for message in completeMessages(from: emission.bytes) {
                let output = try snapshot(
                    endpoints.client.processHandshakeMessage(
                        message.span,
                        at: .handshake
                    )
                )
                clientFlight.emissions.append(contentsOf: output.emissions)
                clientFlight.completed = clientFlight.completed || output.completed
                clientFlight.confirmed = clientFlight.confirmed || output.confirmed
            }
        }

        let clientFinished = try XCTUnwrap(
            clientFlight.emissions.first(where: { $0.level == .handshake })
        )
        var serverConfirmation = Snapshot()
        for message in completeMessages(from: clientFinished.bytes) {
            let output = try snapshot(
                endpoints.server.processHandshakeMessage(
                    message.span,
                    at: .handshake
                )
            )
            serverConfirmation.emissions.append(contentsOf: output.emissions)
            serverConfirmation.completed = serverConfirmation.completed || output.completed
            serverConfirmation.confirmed = serverConfirmation.confirmed || output.confirmed
        }

        XCTAssertTrue(endpoints.client.isEstablished)
        XCTAssertTrue(endpoints.server.isEstablished)
        XCTAssertTrue(serverConfirmation.completed)
        XCTAssertTrue(serverConfirmation.confirmed)
        XCTAssertEqual(
            endpoints.client.negotiatedApplicationProtocol,
            try applicationProtocol()
        )
        XCTAssertEqual(
            try copyTransportParameters(endpoints.client.receivedTransportParameters),
            [0x03, 0x04]
        )
        XCTAssertEqual(
            try copyTransportParameters(endpoints.server.receivedTransportParameters),
            [0x01, 0x02]
        )
    }

    func testCompleteMessageBoundaryRejectsTruncatedHeader() throws {
        var endpoints = try makeEndpoints()
        let start = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(start.emissions.first)
        let truncated = clientHello.bytes.span.extracting(0..<3)

        do {
            _ = try endpoints.server.processHandshakeMessage(truncated, at: .initial)
            XCTFail("truncated TLS handshake message was accepted")
        } catch {
            // Any typed handshake failure is correct here: the input is not a
            // complete TLS handshake message and must never advance the state.
        }
        XCTAssertFalse(endpoints.server.isEstablished)
    }

    private func copyTransportParameters(_ value: OwnedBytes?) throws -> [UInt8] {
        let owned = try XCTUnwrap(value)
        return owned.withBorrowedBytes { bytes in
            var result: [UInt8] = []
            result.reserveCapacity(bytes.count)
            var index = 0
            while index < bytes.count {
                result.append(bytes[index])
                index += 1
            }
            return result
        }
    }

    private func completeMessages(from bytes: OwnedBytes) -> [OwnedBytes] {
        bytes.withBorrowedBytes { input in
            var messages: [OwnedBytes] = []
            var offset = 0
            while offset < input.count {
                guard input.count - offset >= TLS13HandshakeMessageFramer.headerByteCount else {
                    XCTFail("TLS handshake output ended with a truncated header")
                    return messages
                }
                let bodyByteCount =
                    (Int(input[offset + 1]) << 16) |
                    (Int(input[offset + 2]) << 8) |
                    Int(input[offset + 3])
                let messageByteCount =
                    TLS13HandshakeMessageFramer.headerByteCount + bodyByteCount
                guard messageByteCount <= input.count - offset else {
                    XCTFail("TLS handshake output ended with a truncated body")
                    return messages
                }
                messages.append(
                    OwnedBytes(
                        copying: input.extracting(
                            offset..<(offset + messageByteCount)
                        )
                    )
                )
                offset += messageByteCount
            }
            return messages
        }
    }

    private struct Emission {
        let level: QUICHandshakeEncryptionLevel
        let bytes: OwnedBytes
    }

    private struct Snapshot {
        var emissions: [Emission] = []
        var completed = false
        var confirmed = false
    }

    private struct Endpoints: ~Copyable {
        var client: QUICTLSClientHandshake
        var server: QUICTLSServerHandshake
    }

    private func snapshot(
        _ output: consuming QUICTLSStepOutput
    ) throws -> Snapshot {
        var output = consume output
        var result = Snapshot()
        while let effect = try output.nextEffect() {
            switch consume effect {
            case .action(.emitHandshakeBytes(let level, let range)):
                let bytes = try output.withBorrowedBytes { owner throws(ByteError) in
                    guard range.endOffset <= owner.count else {
                        throw .outOfBounds(
                            offset: range.offset,
                            requested: range.count,
                            available: Swift.max(0, owner.count - range.offset)
                        )
                    }
                    return OwnedBytes(
                        copying: owner.extracting(range.offset..<range.endOffset)
                    )
                }
                result.emissions.append(Emission(level: level, bytes: bytes))
            case .action(.handshakeComplete):
                result.completed = true
            case .action(.handshakeConfirmed):
                result.confirmed = true
            case .action(.earlyDataAccepted):
                break
            case .action(.earlyDataRejected):
                break
            case .action(.sendAlert):
                XCTFail("unexpected QUIC TLS alert")
            case .trafficSecret:
                break
            }
        }
        return result
    }

    private func makeEndpoints() throws -> Endpoints {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let certificateDER = deterministicCertificate()
        let certificate = try X509Certificate(der: certificateDER.span)
        let client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x11, count: 32).span
            ),
            certificateValidator: try RFC5280TLS13ServerCertificateValidator(
                trustAnchors: [certificate]
            ),
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            verificationInstant: instant
        )
        let server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x22, count: 32).span
            ),
            certificateDER: certificateDER.span,
            signingKey: TLS13SigningKey(
                ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
            ),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [try applicationProtocol()]
                ),
            transportParameters: ContiguousArray<UInt8>([0x03, 0x04]).span
        )
        return Endpoints(client: client, server: server)
    }

    private func applicationProtocol() throws -> TLS13ApplicationProtocol {
        try TLS13ApplicationProtocol(
            identifier: ContiguousArray([0x68, 0x33]).span
        )
    }

    private func deterministicSeed() -> ContiguousArray<UInt8> {
        [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ]
    }

    private func deterministicCertificate() -> ContiguousArray<UInt8> {
        [
            0x30, 0x81, 0xa6, 0x30, 0x5a, 0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30,
            0x00, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30,
            0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31,
            0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7,
            0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5,
            0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e,
            0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf,
            0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a, 0x30,
            0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41,
            0x00, 0x37, 0xdf, 0xbf, 0x24, 0xeb, 0x69, 0x2e,
            0x0b, 0xe9, 0x24, 0x3a, 0x10, 0xe9, 0x0e, 0x7a,
            0x42, 0x05, 0x28, 0xf6, 0xdc, 0xd6, 0x03, 0x28,
            0x98, 0xdc, 0xa9, 0x56, 0xd5, 0x1c, 0xe3, 0xa2,
            0x86, 0xb1, 0x55, 0x96, 0x38, 0x08, 0x32, 0xa6,
            0x0c, 0xc5, 0x7d, 0x2a, 0x84, 0xf8, 0x43, 0xc7,
            0x74, 0xff, 0xe0, 0xa7, 0xb4, 0x62, 0xa9, 0x55,
            0x6f, 0x76, 0x75, 0x1a, 0x87, 0x0d, 0x5c, 0x79,
            0x01,
        ]
    }

    private func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(span.count)
        for index in 0..<span.count {
            result.append(span[index])
        }
        return result
    }
}
