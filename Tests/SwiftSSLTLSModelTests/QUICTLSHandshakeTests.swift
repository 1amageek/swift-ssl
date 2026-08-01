import XCTest
import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
@testable import SwiftSSLQUIC

final class QUICTLSHandshakeTests: XCTestCase {
    func testOutOfOrderCryptoFramesCompleteHandshakeWithDirectionalSecrets() throws {
        var endpoints = try makeEndpoints()

        let clientStart = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(
            clientStart.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let split = clientHello.count / 2
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: UInt64(split),
            bytes: clientHello.span.extracting(split..<clientHello.count)
        )
        let incomplete = try endpoints.server.processNextMessage(at: .initial)
        switch consume incomplete {
        case .none: break
        case .some: XCTFail("an incomplete ClientHello was processed")
        }
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span.extracting(0..<split)
        )
        guard let serverStep = try endpoints.server.processNextMessage(at: .initial) else {
            return XCTFail("the complete ClientHello was not processed")
        }
        let serverFlight = try snapshot(serverStep)
        let serverHello = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let encryptedFlight = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .handshake })?.bytes
        )

        try endpoints.client.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: serverHello.span
        )
        guard let clientHelloStep = try endpoints.client.processNextMessage(at: .initial) else {
            return XCTFail("the complete ServerHello was not processed")
        }
        let clientServerHello = try snapshot(clientHelloStep)
        XCTAssertEqual(
            clientServerHello.secret(.read, .handshake),
            serverFlight.secret(.write, .handshake)
        )
        XCTAssertEqual(
            clientServerHello.secret(.write, .handshake),
            serverFlight.secret(.read, .handshake)
        )

        try endpoints.client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )
        var clientFinished: OwnedBytes?
        var clientApplicationRead: ContiguousArray<UInt8>?
        var clientApplicationWrite: ContiguousArray<UInt8>?
        var clientCompleted = false
        while let step = try endpoints.client.processNextMessage(at: .handshake) {
            let current = try snapshot(step)
            if let emitted = current.emissions.first(where: { $0.level == .handshake }) {
                clientFinished = emitted.bytes
            }
            if let secret = current.secret(.read, .oneRTT) {
                clientApplicationRead = secret
            }
            if let secret = current.secret(.write, .oneRTT) {
                clientApplicationWrite = secret
            }
            clientCompleted = clientCompleted || current.completed
        }
        XCTAssertTrue(endpoints.client.isEstablished)
        XCTAssertTrue(clientCompleted)
        XCTAssertEqual(
            clientApplicationRead,
            serverFlight.secret(.write, .oneRTT)
        )
        XCTAssertEqual(
            clientApplicationWrite,
            serverFlight.secret(.read, .oneRTT)
        )

        let finished = try XCTUnwrap(clientFinished)
        try endpoints.server.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: finished.span
        )
        guard let confirmationStep = try endpoints.server.processNextMessage(at: .handshake) else {
            return XCTFail("the complete ClientFinished was not processed")
        }
        let confirmation = try snapshot(confirmationStep)
        XCTAssertTrue(endpoints.server.isEstablished)
        XCTAssertTrue(confirmation.completed)
        XCTAssertTrue(confirmation.confirmed)
    }

    func testConflictingCryptoRetransmissionFailsBeforeTLSConsumesMessage() throws {
        var endpoints = try makeEndpoints()
        let start = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(start.emissions.first?.bytes)
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span.extracting(0..<8)
        )
        var conflicting = copy(clientHello.span.extracting(0..<8))
        conflicting[7] ^= 0x01
        do {
            try endpoints.server.receiveCrypto(
                level: .initial,
                offset: 0,
                bytes: conflicting.span
            )
            XCTFail("conflicting CRYPTO retransmission was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .stream(.reassembly(.conflictingOverlap(offset: 7)))
            )
        }
        let incomplete = try endpoints.server.processNextMessage(at: .initial)
        switch consume incomplete {
        case .none: break
        case .some: XCTFail("a partial ClientHello was processed")
        }
    }

    private struct Emission {
        let level: QUICHandshakeEncryptionLevel
        let bytes: OwnedBytes
    }

    private struct SecretKey: Hashable {
        let direction: QUICSecretDirection
        let level: QUICTrafficSecretLevel
    }

    private struct StepSnapshot {
        var emissions: [Emission] = []
        var secrets: [SecretKey: ContiguousArray<UInt8>] = [:]
        var completed = false
        var confirmed = false

        func secret(
            _ direction: QUICSecretDirection,
            _ level: QUICTrafficSecretLevel
        ) -> ContiguousArray<UInt8>? {
            secrets[SecretKey(direction: direction, level: level)]
        }
    }

    private struct Endpoints: ~Copyable {
        var client: QUICTLSClientHandshake
        var server: QUICTLSServerHandshake
    }

    private func snapshot(
        _ output: consuming QUICTLSStepOutput
    ) throws -> StepSnapshot {
        var output = consume output
        var result = StepSnapshot()
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
            case .action(.sendAlert):
                XCTFail("unexpected alert")
            case .trafficSecret(let event):
                result.secrets[
                    SecretKey(direction: event.direction, level: event.level)
                ] = event.withBorrowedSecret { copy($0) }
            }
        }
        return result
    }

    private func makeEndpoints() throws -> Endpoints {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientKey = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        let serverKey = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientKey,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: instant
        )
        let server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverKey,
            certificateDER: deterministicCertificate().span,
            signingKey: .ed25519(signingKey),
            verificationInstant: instant
        )
        return Endpoints(client: client, server: server)
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

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    private func deterministicSeed() -> ContiguousArray<UInt8> {
        bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    }

    private func deterministicServerPublicKey() -> ContiguousArray<UInt8> {
        bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    }

    private func deterministicCertificate() -> ContiguousArray<UInt8> {
        bytes(
            "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a" +
            "170d3235303130313030303030305a3000302a300506032b6570032100" +
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
            "300506032b6570034100" +
            "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b" +
            "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
        )
    }
}
