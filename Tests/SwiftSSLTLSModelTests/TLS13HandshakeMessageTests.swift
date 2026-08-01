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
        XCTAssertEqual(copy(parsed.random.span), Array(random))
        XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
    }

    func testCertificateAndFinishedMessagesHaveStrictLengths() throws {
        let certificate = ContiguousArray<UInt8>([1, 2, 3, 4])
        let certificateMessage = try TLS13HandshakeCodec.makeCertificate(certificateDER: certificate.span)
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
            signatureScheme: .ecdsaP256SHA256,
            signature: signature.span
        )
        let parsed = try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message.span)
        XCTAssertEqual(parsed.signatureScheme, .ecdsaP256SHA256)
        XCTAssertEqual(copy(parsed.signature.span), Array(signature))

        do {
            _ = try TLS13HandshakeCodec.parseCertificateVerify(message.span)
            XCTFail("the Ed25519-only compatibility parser accepted a P-256 scheme")
        } catch {
            XCTAssertEqual(error, .signatureFailure)
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
        let clientEphemeral = try X25519PrivateKey(bytes: ContiguousArray(repeating: 0x11, count: 32).span)
        let serverEphemeral = try X25519PrivateKey(bytes: ContiguousArray(repeating: 0x22, count: 32).span)
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
            signingKey: .ed25519(signingKey),
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

    func testP256ECDSAClientServerHandshakeCompletes() throws {
        let certificate = makeECDSACertificate()
        let privateScalar = bytes(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        let signingKey = try P256PrivateKey(bytes: privateScalar.span)
        let expectedPublicKey = ContiguousArray(copy(signingKey.publicKey().span))
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_750_000_000,
            nanoseconds: 0
        )
        try assertECDSAHandshake(
            certificate: certificate,
            signingKey: .p256(signingKey),
            expectedServerPublicKey: expectedPublicKey,
            signatureScheme: .ecdsaP256SHA256,
            verificationInstant: verificationInstant
        )
    }

    func testP384ECDSAClientServerHandshakeCompletes() throws {
        let certificate = makeP384ECDSACertificate()
        let privateScalar = ContiguousArray<UInt8>(repeating: 0, count: P384PrivateKey.byteCount)
        var scalar = privateScalar
        scalar[scalar.count - 1] = 1
        let signingKey = try P384PrivateKey(bytes: scalar.span)
        let expectedPublicKey = ContiguousArray(copy(signingKey.publicKey().span))
        try assertECDSAHandshake(
            certificate: certificate,
            signingKey: .p384(signingKey),
            expectedServerPublicKey: expectedPublicKey,
            signatureScheme: .ecdsaP384SHA384,
            verificationInstant: try VerificationInstant(
                secondsSinceUnixEpoch: 1_750_000_000,
                nanoseconds: 0
            )
        )
    }

    func testP521ECDSAClientServerHandshakeCompletes() throws {
        let certificate = makeP521ECDSACertificate()
        var scalar = ContiguousArray<UInt8>(repeating: 0, count: P521PrivateKey.byteCount)
        scalar[scalar.count - 1] = 1
        let signingKey = try P521PrivateKey(bytes: scalar.span)
        let expectedPublicKey = ContiguousArray(copy(signingKey.publicKey().span))
        try assertECDSAHandshake(
            certificate: certificate,
            signingKey: .p521(signingKey),
            expectedServerPublicKey: expectedPublicKey,
            signatureScheme: .ecdsaP521SHA512,
            verificationInstant: try VerificationInstant(
                secondsSinceUnixEpoch: 1_750_000_000,
                nanoseconds: 0
            )
        )
    }

    func testP521TLS13SigningKeyRoundTripsTheCertificateVerifyInput() throws {
        var scalar = ContiguousArray<UInt8>(repeating: 0, count: P521PrivateKey.byteCount)
        scalar[scalar.count - 1] = 1
        let key = try P521PrivateKey(bytes: scalar.span)
        let publicKey = try P521PublicKey(bytes: key.publicKey().span)
        let message = ContiguousArray<UInt8>(repeating: 0xA5, count: 98)
        let signingKey = TLS13SigningKey.p521(key)
        let signature = try signingKey.sign(message: message.span)
        var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
        var destination = digest.mutableSpan
        try SHA512.hash(message.span, into: &destination)
        XCTAssertTrue(try P521ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: publicKey.span
        ))
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
            signingKey: .ed25519(signingKey),
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
            signingKey: .ed25519(try Ed25519PrivateKey(seed: deterministicSeed().span)),
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
            signingKey: .ed25519(try Ed25519PrivateKey(seed: deterministicSeed().span)),
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
            signingKey: .ed25519(signingKey),
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
                signingKey: .ed25519(signingKey),
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

    private func assertECDSAHandshake(
        certificate: ContiguousArray<UInt8>,
        signingKey: consuming TLS13SigningKey,
        expectedServerPublicKey: ContiguousArray<UInt8>,
        signatureScheme: TLS13SignatureScheme,
        verificationInstant: VerificationInstant
    ) throws {
        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        let serverEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x31, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: expectedServerPublicKey.span,
            verificationInstant: verificationInstant,
            expectedServerSignatureScheme: signatureScheme
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x32, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: certificate.span,
            signingKey: consume signingKey,
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

    private func makeECDSACertificate() -> ContiguousArray<UInt8> {
        bytes(
            "3082016930820110a003020102020107300a06082a8648ce3d04030230223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d" +
            "3235303130313030303030305a170d3335303130313030303030305a30223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013" +
            "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e" +
            "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f" +
            "9e162bce33576b315ececbb6406837bf51f5a3373035300f0603551d130101ff0405" +
            "30030101ff30220603551d11041b3019821773776966742d73736c2d65636473612e" +
            "6578616d706c65300a06082a8648ce3d040302034700304402207d64b4f0d8d41a49" +
            "720e591dc1844556462cd8beb44558fa9f63156a76f2c6cc022063756eb89655ab0b" +
            "0b04032d184382dd99e0be5ce5cacc66374a36dc83f7ac23"
        )
    }

    private func makeP384ECDSACertificate() -> ContiguousArray<UInt8> {
        bytes(
            "308201833082010aa003020102020101300a06082a8648ce3d0403033021311f301d06035504030c1673776966742d73736c2d703338342e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a3021311f301d06035504030c1673776966742d73736c2d703338342e6578616d706c653076301006072a8648ce3d020106052b8104002203620004aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fa316301430120603551d130101ff040830060101ff020101300a06082a8648ce3d040303036700306402302c8f2d979504b245044527bfeebf34bf0feb065599f5ec0243572bf6481d03487106199aa6ddf1f000b77d6f2718e0a302302efccfa841e832e46c38ec9a2f0268a7274421f49b4db42ceee560ad53d689ad24bb41d443964c77492b2f874012763c"
        )
    }

    private func makeP521ECDSACertificate() -> ContiguousArray<UInt8> {
        bytes(
            "308201ce30820130a003020102020101300a06082a8648ce3d0403043021311f301d06035504030c1673776966742d73736c2d703532312e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a3021311f301d06035504030c1673776966742d73736c2d703532312e6578616d706c6530819b301006072a8648ce3d020106052b81040023038186000400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650a316301430120603551d130101ff040830060101ff020101300a06082a8648ce3d04030403818b00308187024200a71f81d5d29a1241748dc7717dcd56ee91e0869eb6f0e69eefd14ee9cda2f558f3841871e5fba2c035472632c8d5f3f42e02357822b8f85f5d9d5630264b465ccb02412bf9dcec5c8c46299209130519814a6a23def11dc84f5cca92c6eb641a5f47d28d940d1f90aa1d37c0ca934aec75066346b4060b19688e35e476329bdfca289ea0"
        )
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
