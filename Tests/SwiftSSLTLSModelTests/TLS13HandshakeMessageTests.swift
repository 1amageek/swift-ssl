import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import XCTest

final class TLS13HandshakeMessageTests: XCTestCase {
    func testClientHelloRoundTrip() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
        let keyShare = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
        let message = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            keyShare: keyShare.span
        )
        let parsed = try TLS13HandshakeCodec.parseClientHello(message.span)

        XCTAssertEqual(parsed.namedGroup, .x25519)
        XCTAssertEqual(copy(parsed.random.span), Array(random))
        XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
    }

    func testServerHelloRoundTrip() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
        let keyShare = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
        let message = try TLS13HandshakeCodec.makeServerHello(
            random: random.span,
            keyShare: keyShare.span
        )
        let parsed = try TLS13HandshakeCodec.parseServerHello(message.span)

        XCTAssertEqual(parsed.cipherSuite, .aes128GCM_SHA256)
        XCTAssertEqual(parsed.namedGroup, .x25519)
        XCTAssertEqual(copy(parsed.random.span), Array(random))
        XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
    }

    func testHybridKeyShareUsesRoleSpecificWireEncoding() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
        let clientShare = ContiguousArray<UInt8>(repeating: 0x22, count: 1_216)
        let clientMessage = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: .x25519MLKEM768,
            keyShare: clientShare.span
        )
        let parsedClient = try TLS13HandshakeCodec.parseClientHello(clientMessage.span)
        XCTAssertEqual(parsedClient.namedGroup, .x25519MLKEM768)
        XCTAssertEqual(copy(parsedClient.keyShare.span), Array(clientShare))

        let encodedClient = ContiguousArray(copy(clientMessage.span))
        let supportedGroups = try extensionValue(
            type: 0x000A,
            in: encodedClient,
            clientHello: true
        )
        XCTAssertEqual(readUInt16(supportedGroups, at: 0), 2)
        XCTAssertEqual(readUInt16(supportedGroups, at: 2), 0x11EC)
        let clientKeyShare = try extensionValue(
            type: 0x0033,
            in: encodedClient,
            clientHello: true
        )
        XCTAssertEqual(readUInt16(clientKeyShare, at: 0), 1_220)
        XCTAssertEqual(readUInt16(clientKeyShare, at: 2), 0x11EC)
        XCTAssertEqual(readUInt16(clientKeyShare, at: 4), 1_216)
        XCTAssertEqual(clientKeyShare.count, 1_222)

        let serverShare = ContiguousArray<UInt8>(repeating: 0x44, count: 1_120)
        let serverMessage = try TLS13HandshakeCodec.makeServerHello(
            random: random.span,
            namedGroup: .x25519MLKEM768,
            keyShare: serverShare.span
        )
        let parsedServer = try TLS13HandshakeCodec.parseServerHello(serverMessage.span)
        XCTAssertEqual(parsedServer.namedGroup, .x25519MLKEM768)
        XCTAssertEqual(copy(parsedServer.keyShare.span), Array(serverShare))

        let serverKeyShare = try extensionValue(
            type: 0x0033,
            in: ContiguousArray(copy(serverMessage.span)),
            clientHello: false
        )
        XCTAssertEqual(readUInt16(serverKeyShare, at: 0), 0x11EC)
        XCTAssertEqual(readUInt16(serverKeyShare, at: 2), 1_120)
        XCTAssertEqual(serverKeyShare.count, 1_124)
    }

    func testClientKeyShareRejectsInvalidVectorAndGroupMismatch() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
        let clientShare = ContiguousArray<UInt8>(repeating: 0x22, count: 1_216)
        let message = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: .x25519MLKEM768,
            keyShare: clientShare.span
        )

        var invalidVector = ContiguousArray(copy(message.span))
        let keyShareRange = try extensionValueRange(
            type: 0x0033,
            in: invalidVector,
            clientHello: true
        )
        invalidVector[keyShareRange.lowerBound + 1] &-= 1
        do {
            _ = try TLS13HandshakeCodec.parseClientHello(invalidVector.span)
            XCTFail("ClientHello accepted an invalid key_share vector length")
        } catch {
            XCTAssertEqual(error, .invalidKeyShare)
        }

        var groupMismatch = ContiguousArray(copy(message.span))
        let groupsRange = try extensionValueRange(
            type: 0x000A,
            in: groupMismatch,
            clientHello: true
        )
        groupMismatch[groupsRange.lowerBound + 2] = 0x00
        groupMismatch[groupsRange.lowerBound + 3] = 0x1D
        do {
            _ = try TLS13HandshakeCodec.parseClientHello(groupMismatch.span)
            XCTFail("ClientHello accepted a key share absent from supported_groups")
        } catch {
            XCTAssertEqual(error, .invalidKeyShare)
        }
    }

    func testCertificateAndFinishedMessagesHaveStrictLengths() throws {
        let certificate = ContiguousArray<UInt8>([1, 2, 3, 4])
        let certificateMessage = try TLS13HandshakeCodec.makeCertificate(
            certificateDER: certificate.span)
        let parsedCertificate = try TLS13HandshakeCodec.parseCertificate(certificateMessage.span)
        XCTAssertEqual(copy(parsedCertificate.span), Array(certificate))

        let verifyData = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
        let finished = try TLS13HandshakeCodec.makeFinished(verifyData: verifyData.span)
        let parsedFinished = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 32)
        XCTAssertEqual(copy(parsedFinished.span), Array(verifyData))

        do {
            _ = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 48)
            XCTFail("finished message with the wrong hash length was accepted")
        } catch {
            XCTAssertEqual(error, .invalidFinished)
        }
    }

    func testCertificateVerifyCodecCarriesExplicitSignatureScheme() throws {
        let signature = ContiguousArray<UInt8>(repeating: 0x5A, count: 64)
        let message = try TLS13HandshakeCodec.makeCertificateVerify(
            signatureScheme: .ed25519,
            signature: signature.span
        )
        let parsed = try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message.span)
        XCTAssertEqual(parsed.signatureScheme, .ed25519)
        XCTAssertEqual(copy(parsed.signature.span), Array(signature))
        let parsedSignature = try TLS13HandshakeCodec.parseCertificateVerify(message.span)
        XCTAssertEqual(copy(parsedSignature.span), Array(signature))

        var unsupported = ContiguousArray(copy(message.span))
        unsupported[4] = 0x04
        unsupported[5] = 0x03
        do {
            _ = try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(unsupported.span)
            XCTFail("the modern profile accepted an unsupported signature scheme")
        } catch {
            XCTAssertEqual(error, .malformedMessage)
        }
    }

    func testKeyUpdateCodecRejectsInvalidRequestValue() throws {
        let message = try TLS13HandshakeCodec.makeKeyUpdate(requestUpdate: true)
        XCTAssertTrue(try TLS13HandshakeCodec.parseKeyUpdate(message.span))

        var malformed = ContiguousArray(copy(message.span))
        malformed[malformed.count - 1] = 2
        do {
            _ = try TLS13HandshakeCodec.parseKeyUpdate(malformed.span)
            XCTFail("invalid KeyUpdate request value was accepted")
        } catch {
            XCTAssertEqual(error, .malformedMessage)
        }
    }

    func testResumptionStateDerivesSingleUsePSKAndObfuscatedAge() throws {
        let issuedAt = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 500_000_000
        )
        let ticket = ContiguousArray<UInt8>(repeating: 0xA5, count: 24)
        let nonce = ContiguousArray<UInt8>([2, 3, 4])
        let masterSecret = ContiguousArray<UInt8>(0..<32)
        var state = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: masterSecret.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: issuedAt,
            lifetime: 3_600,
            ageAdd: 0x0102_0304
        )

        let nextInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_001,
            nanoseconds: 500_000_000
        )
        XCTAssertEqual(
            try state.obfuscatedTicketAge(at: nextInstant),
            1_000 &+ 0x0102_0304
        )
        state.withTicketBytes { bytes in
            XCTAssertEqual(copy(bytes), Array(ticket))
        }

        let psk = try state.consumePSK()
        psk.withBorrowedBytes { pskBytes in
            XCTAssertEqual(
                copy(pskBytes),
                Array(bytes("73bd90ca427f124a189ef64ee7009d911ba8c213587fa5fec7a7c300a74a9c3e"))
            )
        }
        XCTAssertTrue(state.isConsumed)
        do {
            _ = try state.consumePSK()
            XCTFail("a resumption PSK was consumed more than once")
        } catch {
            XCTAssertEqual(error, .replayDetected)
        }

        let beforeIssue = try VerificationInstant(
            secondsSinceUnixEpoch: 1_719_999_999,
            nanoseconds: 500_000_000
        )
        do {
            _ = try state.obfuscatedTicketAge(at: beforeIssue)
            XCTFail("a ticket age before issuance was accepted")
        } catch {
            XCTAssertEqual(error, .issuedInFuture)
        }

        let afterExpiry = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_003_601,
            nanoseconds: 500_000_000
        )
        do {
            _ = try state.obfuscatedTicketAge(at: afterExpiry)
            XCTFail("an expired ticket was accepted")
        } catch {
            XCTAssertEqual(error, .expired)
        }
    }

    func testDeterministicClientServerHandshakeCompletes() throws {
        let seed = deterministicSeed()
        let serverPublicKey = deterministicServerPublicKey()
        let certificate = deterministicCertificate()
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span)
        let serverEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span)
        let signingKey = try Ed25519PrivateKey(seed: seed.span)
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: serverPublicKey.span,
            verificationInstant: verificationInstant
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: certificate.span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: verificationInstant
        )

        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        let clientFinished = try client.receive(serverFlight.bytes.span)
        let serverFinished = try server.receive(clientFinished.bytes.span)

        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
        XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
        XCTAssertTrue(serverFinished.actions.contains(.handshakeConfirmed))

        let applicationData = ContiguousArray<UInt8>([0x61, 0x70, 0x70, 0x2D, 0x31])
        let applicationOutput = try client.sendApplicationData(applicationData.span)
        let received = try server.receiveApplicationRecord(applicationOutput.bytes.span)
        XCTAssertEqual(copy(received.span), Array(applicationData))

        let response = ContiguousArray<UInt8>([0x6F, 0x6B])
        let responseOutput = try server.sendApplicationData(response.span)
        let clientReceived = try client.receiveApplicationRecord(responseOutput.bytes.span)
        XCTAssertEqual(copy(clientReceived.span), Array(response))

        let clientKeyUpdate = try client.requestKeyUpdate(requestPeerUpdate: true)
        let serverKeyUpdateResponse = try server.receivePostHandshakeRecord(
            clientKeyUpdate.bytes.span
        )
        XCTAssertFalse(serverKeyUpdateResponse.bytes.isEmpty)
        let clientKeyUpdateConsumed = try client.receivePostHandshakeRecord(
            serverKeyUpdateResponse.bytes.span
        )
        XCTAssertTrue(clientKeyUpdateConsumed.bytes.isEmpty)

        let postUpdateClientData = ContiguousArray<UInt8>([0x6E, 0x65, 0x77])
        let postUpdateClientOutput = try client.sendApplicationData(postUpdateClientData.span)
        let postUpdateClientReceived = try server.receiveApplicationRecord(
            postUpdateClientOutput.bytes.span
        )
        XCTAssertEqual(copy(postUpdateClientReceived.span), Array(postUpdateClientData))

        let postUpdateServerData = ContiguousArray<UInt8>([0x6F, 0x6C, 0x64])
        let postUpdateServerOutput = try server.sendApplicationData(postUpdateServerData.span)
        let postUpdateServerReceived = try client.receiveApplicationRecord(
            postUpdateServerOutput.bytes.span
        )
        XCTAssertEqual(copy(postUpdateServerReceived.span), Array(postUpdateServerData))
    }

    func testHybridStreamHandshakeCompletes() throws {
        let verificationInstant = try VerificationInstant(
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
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            keyExchange: clientKeyExchange,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: verificationInstant
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            keyExchange: serverKeyExchange,
            keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: verificationInstant
        )

        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        let clientFinished = try client.receive(serverFlight.bytes.span)
        let confirmation = try server.receive(clientFinished.bytes.span)

        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
        XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
        XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
    }

    func testDeterministicHandshakeSupportsAllTLS13CipherSuites() throws {
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        for cipherSuite in TLSCipherSuite.allCases {
            let clientEphemeral = try X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x11, count: 32).span
            )
            let serverEphemeral = try X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x22, count: 32).span
            )
            let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
            var client = try TLS13ClientHandshake(
                random: ContiguousArray(repeating: 0x01, count: 32).span,
                ephemeralKey: clientEphemeral,
                expectedServerPublicKey: deterministicServerPublicKey().span,
                verificationInstant: verificationInstant,
                cipherSuite: cipherSuite
            )
            var server = try TLS13ServerHandshake(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: serverEphemeral,
                certificateDER: deterministicCertificate().span,
                signingKey: TLS13SigningKey(ed25519: signingKey),
                verificationInstant: verificationInstant
            )

            let clientHello = try client.start()
            let serverFlight = try server.receive(clientHello.bytes.span)
            let clientFinished = try client.receive(serverFlight.bytes.span)
            _ = try server.receive(clientFinished.bytes.span)
            XCTAssertTrue(client.isEstablished, "client did not establish (cipherSuite)")
            XCTAssertTrue(server.isEstablished, "server did not establish (cipherSuite)")
        }
    }

    func testDeterministicPSKResumptionHandshakeCompletesWithoutCertificateFlight() throws {
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let serverVerificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_001,
            nanoseconds: 0
        )
        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
        let masterSecret = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
        var serverState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: masterSecret.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: verificationInstant,
            lifetime: 3_600,
            ageAdd: 7
        )
        let serverPSK = try serverState.consumePSK()
        let clientState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: masterSecret.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: verificationInstant,
            lifetime: 3_600,
            ageAdd: 7
        )

        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        let serverEphemeralBytes = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: verificationInstant,
            resumptionState: consume clientState
        )
        var server = try serverPSK.withBorrowedBytes { psk in
            let serverEphemeral = try X25519PrivateKey(bytes: serverEphemeralBytes.span)
            return try TLS13ServerHandshake(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: serverEphemeral,
                certificateDER: deterministicCertificate().span,
                signingKey: TLS13SigningKey(
                    ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
                ),
                verificationInstant: serverVerificationInstant,
                resumptionIdentity: ticket.span,
                resumptionPSK: psk,
                resumptionIssuedAt: verificationInstant,
                resumptionLifetime: 3_600,
                resumptionAgeAdd: 7
            )
        }

        let clientHello = try client.start()
        let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
            clientHello.bytes.span.extracting(5..<clientHello.bytes.count)
        )
        XCTAssertNotNil(parsedClientHello.preSharedKey)
        let serverFlight = try server.receive(clientHello.bytes.span)
        let clientFinished = try client.receive(serverFlight.bytes.span)
        let serverFinished = try server.receive(clientFinished.bytes.span)

        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
        XCTAssertTrue(serverFinished.actions.contains(.handshakeConfirmed))
    }

    func testNewSessionTicketIsEncryptedAndProducesResumptionState() throws {
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        let serverEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: verificationInstant
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(
                ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
            ),
            verificationInstant: verificationInstant
        )
        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        let clientFinished = try client.receive(serverFlight.bytes.span)
        _ = try server.receive(clientFinished.bytes.span)

        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
        let ticketOutput = try server.sendNewSessionTicket(
            lifetime: 3_600,
            ageAdd: 7,
            ticketNonce: nonce.span,
            ticket: ticket.span
        )
        let state = try client.receiveNewSessionTicket(
            ticketOutput.bytes.span,
            receivedAt: verificationInstant
        )
        state.withTicketBytes { bytes in
            XCTAssertEqual(copy(bytes), Array(ticket))
        }
        XCTAssertEqual(try state.obfuscatedTicketAge(at: verificationInstant), 7)
    }

    func testClientRejectsTamperedServerFlight() throws {
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let serverEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: deterministicCertificate().span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: verificationInstant
        )
        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: verificationInstant
        )

        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        var tampered = ContiguousArray(copy(serverFlight.bytes.span))
        tampered[tampered.count - 1] ^= 0x01

        do {
            _ = try client.receive(tampered.span)
            XCTFail("tampered server flight was accepted")
        } catch let error {
            XCTAssertEqual(error, .record(.authenticationFailed))
        }
    }

    func testServerRejectsCertificateOutsideVerificationWindow() throws {
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let ephemeralKey = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_800_000_000,
            nanoseconds: 0
        )

        do {
            _ = try TLS13ServerHandshake(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: ephemeralKey,
                certificateDER: deterministicCertificate().span,
                signingKey: TLS13SigningKey(ed25519: signingKey),
                verificationInstant: verificationInstant
            )
            XCTFail("certificate outside the verification window was accepted")
        } catch let error {
            XCTAssertEqual(error, .certificateNotValid)
        }
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }

    private func extensionValue(
        type: UInt16,
        in message: ContiguousArray<UInt8>,
        clientHello: Bool
    ) throws -> ContiguousArray<UInt8> {
        let range = try extensionValueRange(
            type: type,
            in: message,
            clientHello: clientHello
        )
        return ContiguousArray(message[range])
    }

    private func extensionValueRange(
        type: UInt16,
        in message: ContiguousArray<UInt8>,
        clientHello: Bool
    ) throws -> Range<Int> {
        let extensionsStart = clientHello ? 47 : 44
        guard message.count >= extensionsStart else {
            throw TLS13HandshakeError.malformedMessage
        }
        let extensionsByteCount = Int(readUInt16(message, at: extensionsStart - 2))
        let extensionsEnd = extensionsStart + extensionsByteCount
        guard extensionsEnd == message.count else {
            throw TLS13HandshakeError.malformedMessage
        }
        var offset = extensionsStart
        while offset < extensionsEnd {
            guard offset + 4 <= extensionsEnd else {
                throw TLS13HandshakeError.malformedMessage
            }
            let extensionType = readUInt16(message, at: offset)
            let valueByteCount = Int(readUInt16(message, at: offset + 2))
            let valueStart = offset + 4
            let valueEnd = valueStart + valueByteCount
            guard valueEnd <= extensionsEnd else {
                throw TLS13HandshakeError.malformedMessage
            }
            if extensionType == type {
                return valueStart..<valueEnd
            }
            offset = valueEnd
        }
        throw TLS13HandshakeError.unsupportedExtension(type)
    }

    private func readUInt16(
        _ bytes: ContiguousArray<UInt8>,
        at offset: Int
    ) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
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
