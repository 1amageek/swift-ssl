import SwiftSSLCore
import SwiftSSLCrypto
import XCTest

@testable import SwiftSSLTLS

final class TLS13HandshakeCoreTests: XCTestCase {
    func testHybridClientServerHandshakeCompletesThroughCore() throws {
        var pair = try makeHybridCorePair()

        let clientHelloOutput = try pair.client.start()
        let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
            clientHelloOutput.bytes.span
        )
        XCTAssertEqual(parsedClientHello.namedGroup, .x25519MLKEM768)
        XCTAssertEqual(parsedClientHello.keyShare.count, 1_216)

        let serverOutput = try pair.server.receiveHandshakeMessage(
            clientHelloOutput.bytes.span,
            at: .initial
        )
        guard case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
            case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
        else {
            return XCTFail("hybrid server core emitted an invalid effect order")
        }
        let serverHello = OwnedBytes(
            copying: try serverOutput.bytes.span(in: serverHelloRange)
        )
        let parsedServerHello = try TLS13HandshakeCodec.parseServerHello(serverHello.span)
        XCTAssertEqual(parsedServerHello.namedGroup, .x25519MLKEM768)
        XCTAssertEqual(parsedServerHello.keyShare.count, 1_120)
        _ = try pair.client.receiveHandshakeMessage(serverHello.span, at: .initial)

        let serverFlight = try serverOutput.bytes.span(in: serverFlightRange)
        let messages = try TLS13HandshakeCodec.splitMessages(serverFlight)
        var clientFinished: OwnedBytes?
        for message in messages {
            let output = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
            for action in output.actions {
                if case .emitHandshakeBytes(.handshake, let range) = action {
                    clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
                }
            }
        }
        guard let clientFinished else {
            return XCTFail("hybrid client core did not emit Finished")
        }
        _ = try pair.server.receiveHandshakeMessage(clientFinished.span, at: .handshake)

        XCTAssertTrue(pair.client.isEstablished)
        XCTAssertTrue(pair.server.isEstablished)
    }

    func testServerCoreRejectsUnexpectedNamedGroup() throws {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientKey = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        var client = try TLS13ClientHandshakeCore(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientKey,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: instant
        )
        let hybridServer = try TLS13X25519MLKEM768ServerKeyExchange.generate(
            using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
        )
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        var server = try TLS13ServerHandshakeCore(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            keyExchange: hybridServer,
            keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant
        )

        let clientHello = try client.start()
        do {
            _ = try server.receiveHandshakeMessage(clientHello.bytes.span, at: .initial)
            XCTFail("server accepted an unexpected named group")
        } catch {
            XCTAssertEqual(
                error,
                .keyExchange(
                    .unexpectedNamedGroup(
                        expected: .x25519MLKEM768,
                        actual: .x25519
                    ))
            )
        }
    }

    func testRecordIndependentClientServerHandshakeCompletesWithMatchingSecrets() throws {
        var pair = try makeCorePair()

        let clientHelloOutput = try pair.client.start()
        guard
            case .emitHandshakeBytes(.initial, let clientHelloRange) =
                clientHelloOutput.actions.first
        else {
            return XCTFail("missing ClientHello action")
        }
        let clientHello = OwnedBytes(
            copying: try clientHelloOutput.bytes.span(in: clientHelloRange)
        )

        var serverOutput = try pair.server.receiveHandshakeMessage(
            clientHello.span,
            at: .initial
        )
        guard serverOutput.actions.count == 4,
            case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
            case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
        else {
            return XCTFail("server core emitted an invalid effect order")
        }
        let serverHello = OwnedBytes(
            copying: try serverOutput.bytes.span(in: serverHelloRange)
        )
        let serverFlight = OwnedBytes(
            copying: try serverOutput.bytes.span(in: serverFlightRange)
        )
        var serverHandshakeSecrets: SecretSnapshot?
        var serverApplicationSecrets: SecretSnapshot?
        while let effect = try serverOutput.nextEffect() {
            switch consume effect {
            case .trafficSecrets(.handshake, let secrets):
                serverHandshakeSecrets = copySecrets(secrets)
            case .trafficSecrets(.application, let secrets):
                serverApplicationSecrets = copySecrets(secrets)
            case .action:
                break
            case .trafficSecrets:
                return XCTFail("unexpected traffic-secret epoch")
            }
        }

        var clientServerHelloOutput = try pair.client.receiveHandshakeMessage(
            serverHello.span,
            at: .initial
        )
        var clientHandshakeSecrets: SecretSnapshot?
        while let effect = try clientServerHelloOutput.nextEffect() {
            switch consume effect {
            case .trafficSecrets(.handshake, let secrets):
                clientHandshakeSecrets = copySecrets(secrets)
            case .action:
                break
            case .trafficSecrets:
                return XCTFail("unexpected traffic-secret epoch")
            }
        }
        XCTAssertEqual(clientHandshakeSecrets, serverHandshakeSecrets)

        let messages = try TLS13HandshakeCodec.splitMessages(serverFlight.span)
        var clientFinished: OwnedBytes?
        var clientApplicationSecrets: SecretSnapshot?
        for message in messages {
            var output = try pair.client.receiveHandshakeMessage(
                message.span,
                at: .handshake
            )
            for action in output.actions {
                if case .emitHandshakeBytes(.handshake, let range) = action {
                    clientFinished = OwnedBytes(
                        copying: try output.bytes.span(in: range)
                    )
                    XCTAssertEqual(
                        output.actions,
                        [
                            .emitHandshakeBytes(epoch: .handshake, bytes: range),
                            .installTrafficSecrets(epoch: .application),
                            .handshakeComplete,
                        ]
                    )
                }
            }
            while let effect = try output.nextEffect() {
                switch consume effect {
                case .trafficSecrets(.application, let secrets):
                    clientApplicationSecrets = copySecrets(secrets)
                case .action:
                    break
                case .trafficSecrets:
                    return XCTFail("unexpected traffic-secret epoch")
                }
            }
        }
        XCTAssertTrue(pair.client.isEstablished)
        XCTAssertEqual(clientApplicationSecrets, serverApplicationSecrets)
        guard let clientFinished else {
            return XCTFail("missing ClientFinished")
        }

        var confirmation = try pair.server.receiveHandshakeMessage(
            clientFinished.span,
            at: .handshake
        )
        var completed = false
        var confirmed = false
        while let effect = try confirmation.nextEffect() {
            switch consume effect {
            case .action(.handshakeComplete): completed = true
            case .action(.handshakeConfirmed): confirmed = true
            case .action: break
            case .trafficSecrets: break
            }
        }
        XCTAssertTrue(pair.server.isEstablished)
        XCTAssertTrue(completed)
        XCTAssertTrue(confirmed)
    }

    func testClientRejectsTamperedRecordIndependentServerFinished() throws {
        var pair = try makeCorePair()
        let clientHelloOutput = try pair.client.start()
        let clientHello = clientHelloOutput.bytes
        let serverOutput = try pair.server.receiveHandshakeMessage(
            clientHello.span,
            at: .initial
        )
        guard case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
            case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
        else {
            return XCTFail("missing server flight")
        }
        let serverHello = OwnedBytes(copying: try serverOutput.bytes.span(in: serverHelloRange))
        let serverFlight = OwnedBytes(copying: try serverOutput.bytes.span(in: serverFlightRange))
        _ = try pair.client.receiveHandshakeMessage(serverHello.span, at: .initial)
        var messages = try TLS13HandshakeCodec.splitMessages(serverFlight.span)
        guard let originalFinished = messages.popLast() else {
            return XCTFail("missing ServerFinished")
        }
        for message in messages {
            _ = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
        }
        var tampered = copy(originalFinished.span)
        tampered[tampered.count - 1] ^= 0x01
        do {
            _ = try pair.client.receiveHandshakeMessage(tampered.span, at: .handshake)
            XCTFail("tampered ServerFinished was accepted")
        } catch {
            XCTAssertEqual(error, .certificateVerifyFailure)
        }
        XCTAssertFalse(pair.client.isEstablished)
    }

    func testCoreRejectsMessageAtWrongEpochAndEntersFailedState() throws {
        var pair = try makeCorePair()
        let clientHelloOutput = try pair.client.start()
        do {
            _ = try pair.server.receiveHandshakeMessage(
                clientHelloOutput.bytes.span,
                at: .handshake
            )
            XCTFail("ClientHello was accepted at the handshake epoch")
        } catch {
            XCTAssertEqual(error, .malformedInput)
        }
        do {
            _ = try pair.server.receiveHandshakeMessage(
                clientHelloOutput.bytes.span,
                at: .initial
            )
            XCTFail("a failed core accepted another message")
        } catch {
            XCTAssertEqual(error, .invalidState)
        }
    }

    func testRecordIndependentPSKResumptionOmitsCertificateFlight() throws {
        let issuedAt = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let receivedAt = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_001,
            nanoseconds: 0
        )
        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
        let master = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
        var serverState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: master.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: issuedAt,
            lifetime: 3_600,
            ageAdd: 7
        )
        let serverPSK = try serverState.consumePSK()
        let clientState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: master.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: issuedAt,
            lifetime: 3_600,
            ageAdd: 7
        )
        var client = try TLS13ClientHandshakeCore(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x11, count: 32).span
            ),
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: issuedAt,
            resumptionState: clientState
        )
        var server = try serverPSK.withBorrowedBytes { psk in
            try TLS13ServerHandshakeCore(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: X25519PrivateKey(
                    bytes: ContiguousArray(repeating: 0x22, count: 32).span
                ),
                certificateDER: deterministicCertificate().span,
                signingKey: TLS13SigningKey(
                    ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
                ),
                verificationInstant: receivedAt,
                resumptionIdentity: ticket.span,
                resumptionPSK: psk,
                resumptionIssuedAt: issuedAt,
                resumptionLifetime: 3_600,
                resumptionAgeAdd: 7
            )
        }

        let clientHello = try client.start()
        let parsed = try TLS13HandshakeCodec.parseClientHello(clientHello.bytes.span)
        XCTAssertNotNil(parsed.preSharedKey)
        let serverOutput = try server.receiveHandshakeMessage(
            clientHello.bytes.span,
            at: .initial
        )
        guard case .emitHandshakeBytes(.initial, let helloRange) = serverOutput.actions[0],
            case .emitHandshakeBytes(.handshake, let flightRange) = serverOutput.actions[2]
        else {
            return XCTFail("missing resumed server flight")
        }
        let serverHello = OwnedBytes(copying: try serverOutput.bytes.span(in: helloRange))
        let flight = OwnedBytes(copying: try serverOutput.bytes.span(in: flightRange))
        let messages = try TLS13HandshakeCodec.splitMessages(flight.span)
        XCTAssertEqual(messages.count, 2)
        XCTAssertEqual(messages[0][0], TLS13HandshakeCodec.encryptedExtensionsType)
        XCTAssertEqual(messages[1][0], TLS13HandshakeCodec.finishedType)

        _ = try client.receiveHandshakeMessage(serverHello.span, at: .initial)
        var clientFinished: OwnedBytes?
        for message in messages {
            let output = try client.receiveHandshakeMessage(message.span, at: .handshake)
            for action in output.actions {
                if case .emitHandshakeBytes(.handshake, let range) = action {
                    clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
                }
            }
        }
        guard let clientFinished else { return XCTFail("missing ClientFinished") }
        _ = try server.receiveHandshakeMessage(clientFinished.span, at: .handshake)
        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
    }

    func testCoreOutputRejectsInitialTrafficSecretInstallation() throws {
        do {
            let output = try TLS13HandshakeCoreOutput(
                bytes: OwnedBytes(),
                actions: [.installTrafficSecrets(epoch: .initial)]
            )
            _ = output.remainingEffectCount
            XCTFail("initial traffic-secret installation was accepted")
        } catch {
            XCTAssertEqual(error, .missingTrafficSecrets(.initial))
        }
    }

    private struct SecretSnapshot: Equatable {
        let client: ContiguousArray<UInt8>
        let server: ContiguousArray<UInt8>
    }

    private struct CorePair: ~Copyable {
        var client: TLS13ClientHandshakeCore
        var server: TLS13ServerHandshakeCore
    }

    private func makeCorePair() throws -> CorePair {
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
        let client = try TLS13ClientHandshakeCore(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientKey,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: instant
        )
        let server = try TLS13ServerHandshakeCore(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverKey,
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant
        )
        return CorePair(client: client, server: server)
    }

    private func makeHybridCorePair() throws -> CorePair {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientKeyExchange = try TLS13X25519MLKEM768ClientKeyExchange.generate(
            mlkemEntropy: FixedEntropy(bytes: sequential(count: 64, seed: 0x10)),
            x25519Entropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x30))
        )
        let serverKeyExchange = try TLS13X25519MLKEM768ServerKeyExchange.generate(
            using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
        )
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let client = try TLS13ClientHandshakeCore(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            keyExchange: clientKeyExchange,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: instant
        )
        let server = try TLS13ServerHandshakeCore(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            keyExchange: serverKeyExchange,
            keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant
        )
        return CorePair(client: client, server: server)
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

    private func sequential(count: Int, seed: UInt8) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(count)
        var index = 0
        while index < count {
            result.append(seed &+ UInt8(truncatingIfNeeded: index))
            index += 1
        }
        return result
    }

    private func copySecrets(
        _ secrets: consuming TLS13TrafficSecretPair
    ) -> SecretSnapshot {
        let client = secrets.withClientSecret { copy($0) }
        let server = secrets.withServerSecret { copy($0) }
        return SecretSnapshot(client: client, server: server)
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
            "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a"
                + "170d3235303130313030303030305a3000302a300506032b6570032100"
                + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                + "300506032b6570034100"
                + "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b"
                + "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
        )
    }
}
