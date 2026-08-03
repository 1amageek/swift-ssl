import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import SwiftSSLX509
import XCTest

@testable import SwiftSSLQUIC

final class QUICTLSHandshakeTests: XCTestCase {
    func testExternalServerCredentialCompletesThroughQUICTransitions() throws {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_704_153_600,
            nanoseconds: 0
        )
        let certificateDER = try delegatedCredentialCertificate()
        let certificate = try X509Certificate(der: certificateDER.span)
        let certificateSigningKey = TLS13SigningKey(
            ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        )
        let delegatedSigner = try Ed25519PrivateKey(
            seed: ContiguousArray(repeating: 0x42, count: 32).span
        )
        let delegatedCredential = try TLS13DelegatedCredential.issue(
            validTime: 3 * 24 * 60 * 60,
            certificateVerifyAlgorithm: .ed25519,
            subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
                publicKey: try delegatedSigner.publicKey()
            ).span,
            certificate: certificate,
            role: .server,
            certificateSigningKey: certificateSigningKey,
            at: instant
        )
        var client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
            ),
            certificateValidator: try makeCertificateValidator(
                certificateDER: certificateDER
            ),
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            verificationInstant: instant
        )
        var server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
            ),
            externalServerCredential: TLS13ExternalServerCredential(),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [try applicationProtocol()]
                ),
            transportParameters: ContiguousArray<UInt8>([0x03, 0x04]).span
        )
        let clientCompression = TrackingCertificateCompressionCodec()
        let serverCompression = TrackingCertificateCompressionCodec()
        try client.configureCertificateCompression(
            TLS13CertificateCompressionConfiguration(
                codecs: [clientCompression]
            )
        )
        try server.configureCertificateCompression(
            TLS13CertificateCompressionConfiguration(
                codecs: [serverCompression]
            )
        )
        let clientStart = try snapshot(client.start())
        let clientHello = try XCTUnwrap(clientStart.emissions.first?.bytes)
        try server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span
        )
        let optionalSelectionTransition = try server.processNextMessageStep(
            at: .initial
        )
        let selectionTransition: QUICTLSHandshakeTransition
        switch consume optionalSelectionTransition {
        case .some(let transition):
            selectionTransition = transition
        case .none:
            return XCTFail("server did not process ClientHello")
        }
        let selectionRequest: TLS13CredentialSelectionRequest
        switch consume selectionTransition {
        case .suspended(.credentialSelection(let request)):
            selectionRequest = request
        case .suspended:
            return XCTFail("unexpected external capability request")
        case .output(let output):
            _ = try snapshot(output)
            return XCTFail("server credential selection did not suspend")
        }
        let credential = try TLS13CredentialDescriptor(
            identifier: ContiguousArray("quic-server-key".utf8).span,
            certificateEntries: [
                try TLS13CertificateEntry(
                    certificateDER: certificateDER.span,
                    delegatedCredential: delegatedCredential
                )
            ],
            signatureScheme: .ed25519,
            verificationInstant: instant
        )
        let signatureTransition = try server.resume(
            .credentialSelected(selectionRequest.token, credential)
        )
        let signatureRequest: TLS13SignatureRequest
        switch consume signatureTransition {
        case .suspended(.signature(let request)):
            signatureRequest = request
        case .suspended:
            return XCTFail("unexpected external capability request")
        case .output(let output):
            _ = try snapshot(output)
            return XCTFail("server signature did not suspend")
        }
        let signature = try delegatedSigner.sign(
            message: signatureRequest.message.span
        )
        let serverTransition = try server.resume(
            .signature(
                signatureRequest.token,
                OwnedBytes(consuming: signature)
            )
        )
        let serverFlight: StepSnapshot
        switch consume serverTransition {
        case .output(let output):
            serverFlight = try snapshot(output)
        case .suspended:
            return XCTFail("verified signature suspended again")
        }
        let serverHello = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let encryptedFlight = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .handshake })?.bytes
        )
        try client.receiveCrypto(level: .initial, offset: 0, bytes: serverHello.span)
        _ = try client.processNextMessage(at: .initial)
        try client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )
        var clientFinished: OwnedBytes?
        while let step = try client.processNextMessage(at: .handshake) {
            let current = try snapshot(step)
            if let emitted = current.emissions.first {
                clientFinished = emitted.bytes
            }
        }
        let finished = try XCTUnwrap(clientFinished)
        try server.receiveCrypto(level: .handshake, offset: 0, bytes: finished.span)
        _ = try server.processNextMessage(at: .handshake)
        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
        XCTAssertEqual(serverCompression.compressionCallCount, 1)
        XCTAssertEqual(clientCompression.decompressionCallCount, 1)
    }

    func testExternalServerTrustCompletesThroughQUICTransitions() throws {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let certificateDER = deterministicCertificate()
        var client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
            ),
            externalServerTrust: TLS13ExternalServerTrust(),
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            serverName: ContiguousArray("server.example".utf8).span,
            verificationInstant: instant
        )
        var server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
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
        let clientStart = try snapshot(client.start())
        let clientHello = try XCTUnwrap(clientStart.emissions.first?.bytes)
        try server.receiveCrypto(level: .initial, offset: 0, bytes: clientHello.span)
        let optionalServerStep = try server.processNextMessage(at: .initial)
        let serverStep: QUICTLSStepOutput
        switch consume optionalServerStep {
        case .some(let output):
            serverStep = output
        case .none:
            return XCTFail("server did not process ClientHello")
        }
        let serverFlight = try snapshot(serverStep)
        let serverHello = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let encryptedFlight = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .handshake })?.bytes
        )
        try client.receiveCrypto(level: .initial, offset: 0, bytes: serverHello.span)
        let initialStep = try client.processNextMessageStep(at: .initial)
        switch consume initialStep {
        case .some(.output(let output)):
            _ = try snapshot(output)
        case .some(.suspended):
            return XCTFail("client did not process ServerHello")
        case .none:
            return XCTFail("client did not process ServerHello")
        }
        try client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )
        var clientFinished: OwnedBytes?
        var sawTrustRequest = false
        while let transition = try client.processNextMessageStep(at: .handshake) {
            switch consume transition {
            case .output(let output):
                let current = try snapshot(output)
                if let emitted = current.emissions.first {
                    clientFinished = emitted.bytes
                }
            case .suspended(.peerTrustEvaluation(let request)):
                XCTAssertEqual(request.peer, .server)
                let resumed = try client.resume(.peerTrustAccepted(request.token))
                switch consume resumed {
                case .output(let output):
                    _ = try snapshot(output)
                case .suspended:
                    return XCTFail("accepted trust result suspended again")
                }
                sawTrustRequest = true
            case .suspended:
                return XCTFail("unexpected external capability request")
            }
        }
        XCTAssertTrue(sawTrustRequest)
        let finished = try XCTUnwrap(clientFinished)
        try server.receiveCrypto(level: .handshake, offset: 0, bytes: finished.span)
        _ = try server.processNextMessage(at: .handshake)
        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
    }

    func testServerRejectsNoCommonApplicationProtocol() throws {
        var endpoints = try makeEndpoints(
            serverProtocolIdentifier: "hq-interop"
        )
        let start = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(
            start.emissions.first(where: { $0.level == .initial })?.bytes
        )
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span
        )

        do {
            _ = try endpoints.server.processNextMessage(at: .initial)
            XCTFail("QUIC TLS accepted no common application protocol")
        } catch {
            XCTAssertEqual(
                error,
                .handshake(.applicationProtocol(.noApplicationProtocol))
            )
        }
    }

    func testHybridHandshakeCompletesThroughQUICCryptoStreams() throws {
        var endpoints = try makeHybridEndpoints()

        let clientStart = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(
            clientStart.emissions.first(where: { $0.level == .initial })?.bytes
        )
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span
        )
        guard let serverStep = try endpoints.server.processNextMessage(at: .initial) else {
            return XCTFail("hybrid server did not process ClientHello")
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
        guard let clientInitialStep = try endpoints.client.processNextMessage(at: .initial) else {
            return XCTFail("hybrid client did not process ServerHello")
        }
        _ = try snapshot(clientInitialStep)
        try endpoints.client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )

        var clientFinished: OwnedBytes?
        while let step = try endpoints.client.processNextMessage(at: .handshake) {
            let current = try snapshot(step)
            if let emitted = current.emissions.first(where: { $0.level == .handshake }) {
                clientFinished = emitted.bytes
            }
        }
        let finished = try XCTUnwrap(clientFinished)
        try endpoints.server.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: finished.span
        )
        guard let confirmation = try endpoints.server.processNextMessage(at: .handshake) else {
            return XCTFail("hybrid server did not process ClientFinished")
        }
        _ = try snapshot(confirmation)

        XCTAssertTrue(endpoints.client.isEstablished)
        XCTAssertTrue(endpoints.server.isEstablished)
        XCTAssertEqual(
            endpoints.client.negotiatedApplicationProtocol,
            try applicationProtocol()
        )
        let clientParameters = try XCTUnwrap(
            endpoints.client.receivedTransportParameters
        )
        let serverParameters = try XCTUnwrap(
            endpoints.server.receivedTransportParameters
        )
        XCTAssertEqual(copy(clientParameters.span), [0x03, 0x04])
        XCTAssertEqual(copy(serverParameters.span), [0x01, 0x02])

        let clientWriteUpdate = try endpoints.client
            .updateOneRTTTrafficSecret(for: .write)
        let serverReadUpdate = try endpoints.server
            .updateOneRTTTrafficSecret(for: .read)
        let clientUpdatedSecret = clientWriteUpdate.withBorrowedSecret {
            copy($0)
        }
        let serverUpdatedSecret = serverReadUpdate.withBorrowedSecret {
            copy($0)
        }
        XCTAssertEqual(clientUpdatedSecret, serverUpdatedSecret)
    }

    func testP256HandshakeCompletesThroughQUICCryptoStreams() throws {
        var endpoints = try makeP256Endpoints()

        let clientStart = try snapshot(endpoints.client.start())
        let clientHello = try XCTUnwrap(
            clientStart.emissions.first(where: { $0.level == .initial })?.bytes
        )
        try endpoints.server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span
        )
        guard let serverStep = try endpoints.server.processNextMessage(at: .initial) else {
            return XCTFail("P-256 server did not process ClientHello")
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
        guard let clientInitialStep = try endpoints.client.processNextMessage(at: .initial) else {
            return XCTFail("P-256 client did not process ServerHello")
        }
        _ = try snapshot(clientInitialStep)
        try endpoints.client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )

        var clientFinished: OwnedBytes?
        while let step = try endpoints.client.processNextMessage(at: .handshake) {
            let current = try snapshot(step)
            if let emitted = current.emissions.first(where: { $0.level == .handshake }) {
                clientFinished = emitted.bytes
            }
        }
        let finished = try XCTUnwrap(clientFinished)
        try endpoints.server.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: finished.span
        )
        guard let confirmation = try endpoints.server.processNextMessage(at: .handshake) else {
            return XCTFail("P-256 server did not process ClientFinished")
        }
        _ = try snapshot(confirmation)

        XCTAssertTrue(endpoints.client.isEstablished)
        XCTAssertTrue(endpoints.server.isEstablished)
        XCTAssertEqual(
            endpoints.client.negotiatedApplicationProtocol,
            try applicationProtocol()
        )
    }

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
        var serverCompleted = false
        var serverConfirmed = false
        while let confirmationStep = try endpoints.server.processNextMessage(
            at: .handshake
        ) {
            let confirmation = try snapshot(confirmationStep)
            serverCompleted = serverCompleted || confirmation.completed
            serverConfirmed = serverConfirmed || confirmation.confirmed
        }
        XCTAssertTrue(endpoints.server.isEstablished)
        XCTAssertNotNil(endpoints.server.authenticatedClientIdentity)
        XCTAssertTrue(serverCompleted)
        XCTAssertTrue(serverConfirmed)
    }

    func testZeroRTTSecretIsDirectionalAndQUICOmitsEndOfEarlyData() throws {
        let issuedAt = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let receivedAt = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_001,
            nanoseconds: 0
        )
        let protocolValue = try applicationProtocol()
        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let nonce = ContiguousArray<UInt8>([1, 2, 3])
        let master = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
        var serverState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: master.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: issuedAt,
            lifetime: 3_600,
            ageAdd: 7,
            maximumEarlyDataByteCount: UInt32.max,
            applicationProtocol: protocolValue
        )
        let serverPSK = try serverState.consumePSK()
        let clientState = try TLS13ResumptionState(
            ticket: ticket.span,
            ticketNonce: nonce.span,
            resumptionMasterSecret: master.span,
            cipherSuite: .aes128GCM_SHA256,
            issuedAt: issuedAt,
            lifetime: 3_600,
            ageAdd: 7,
            maximumEarlyDataByteCount: UInt32.max,
            applicationProtocol: protocolValue
        )
        let certificateDER = deterministicCertificate()
        var client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x11, count: 32).span
            ),
            certificateValidator: try makeCertificateValidator(
                certificateDER: certificateDER
            ),
            applicationProtocols: [protocolValue],
            transportParameters: ContiguousArray<UInt8>([1, 2]).span,
            verificationInstant: issuedAt,
            resumptionState: clientState,
            earlyDataConfiguration: try TLS13EarlyDataClientConfiguration(
                maximumByteCount: UInt32.max
            )
        )
        var server = try serverPSK.withBorrowedBytes { psk in
            try QUICTLSServerHandshake.make(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: X25519PrivateKey(
                    bytes: ContiguousArray(repeating: 0x22, count: 32).span
                ),
                certificateDER: certificateDER.span,
                signingKey: TLS13SigningKey(
                    ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
                ),
                verificationInstant: receivedAt,
                applicationProtocolSelector:
                    try ServerPreferredTLS13ApplicationProtocolSelector(
                        supportedProtocols: [protocolValue]
                    ),
                transportParameters: ContiguousArray<UInt8>([3, 4]).span,
                resumptionIdentity: ticket.span,
                resumptionPSK: psk,
                resumptionIssuedAt: issuedAt,
                resumptionLifetime: 3_600,
                resumptionAgeAdd: 7,
                resumptionMaximumEarlyDataByteCount: UInt32.max,
                resumptionApplicationProtocol: protocolValue,
                earlyDataConfiguration: try TLS13EarlyDataServerConfiguration(
                    maximumByteCount: UInt32.max,
                    replayProtector: AcceptingEarlyDataReplayProtector()
                )
            )
        }

        let clientStart = try snapshot(client.start())
        let clientHello = try XCTUnwrap(
            clientStart.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let clientZeroRTT = try XCTUnwrap(
            clientStart.secret(.write, .zeroRTT)
        )
        XCTAssertNil(clientStart.secret(.read, .zeroRTT))

        try server.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: clientHello.span
        )
        guard let serverStep = try server.processNextMessage(at: .initial) else {
            XCTFail("server did not process ClientHello")
            return
        }
        let serverFlight = try snapshot(serverStep)
        XCTAssertEqual(
            serverFlight.secret(.read, .zeroRTT),
            clientZeroRTT
        )
        XCTAssertNil(serverFlight.secret(.write, .zeroRTT))
        XCTAssertTrue(serverFlight.earlyDataAccepted)

        let serverHello = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .initial })?.bytes
        )
        let encryptedFlight = try XCTUnwrap(
            serverFlight.emissions.first(where: { $0.level == .handshake })?.bytes
        )
        try client.receiveCrypto(
            level: .initial,
            offset: 0,
            bytes: serverHello.span
        )
        _ = try client.processNextMessage(at: .initial)
        try client.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: encryptedFlight.span
        )
        var clientFinished: OwnedBytes?
        var clientAccepted = false
        while let step = try client.processNextMessage(at: .handshake) {
            let current = try snapshot(step)
            clientAccepted = clientAccepted || current.earlyDataAccepted
            if let emitted = current.emissions.first {
                XCTAssertEqual(emitted.level, .handshake)
                clientFinished = emitted.bytes
            }
        }
        XCTAssertTrue(clientAccepted)
        XCTAssertEqual(client.earlyDataState, TLS13EarlyDataState.accepted)
        let finished = try XCTUnwrap(clientFinished)
        try server.receiveCrypto(
            level: .handshake,
            offset: 0,
            bytes: finished.span
        )
        _ = try server.processNextMessage(at: .handshake)
        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
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
        var earlyDataAccepted = false
        var earlyDataRejected = false

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
            case .action(.earlyDataAccepted):
                result.earlyDataAccepted = true
            case .action(.earlyDataRejected):
                result.earlyDataRejected = true
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

    private func makeEndpoints(
        serverProtocolIdentifier: String = "h3"
    ) throws -> Endpoints {
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
        let certificateDER = deterministicCertificate()
        let certificate = try X509Certificate(der: certificateDER.span)
        let clientIdentity = try TLS13ClientIdentity(
            certificateEntries: [
                try TLS13CertificateEntry(certificateDER: certificateDER.span)
            ],
            signingKey: TLS13SigningKey(
                ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
            ),
            verificationInstant: instant
        )
        let client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientKey,
            certificateValidator: try makeCertificateValidator(
                certificateDER: certificateDER
            ),
            clientIdentity: clientIdentity,
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            verificationInstant: instant
        )
        let server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverKey,
            certificateDER: certificateDER.span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [
                        try applicationProtocol(serverProtocolIdentifier)
                    ]
                ),
            clientAuthentication: TLS13ClientAuthenticationConfiguration(
                requirement: .required,
                validator: try RFC5280TLS13ClientCertificateValidator(
                    trustAnchors: [certificate]
                )
            ),
            transportParameters: ContiguousArray<UInt8>([0x03, 0x04]).span
        )
        return Endpoints(client: client, server: server)
    }

    private func makeHybridEndpoints() throws -> Endpoints {
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
        let certificateDER = deterministicCertificate()
        let client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            keyExchange: clientKeyExchange,
            certificateValidator: try makeCertificateValidator(
                certificateDER: certificateDER
            ),
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            verificationInstant: instant
        )
        let server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            keyExchange: serverKeyExchange,
            keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
            certificateDER: certificateDER.span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [try applicationProtocol()]
                ),
            transportParameters: ContiguousArray<UInt8>([0x03, 0x04]).span
        )
        return Endpoints(client: client, server: server)
    }

    private func makeP256Endpoints() throws -> Endpoints {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientKeyExchange = try TLS13P256ClientKeyExchange.generate(
            using: FixedEntropy(bytes: ContiguousArray(repeating: 0x11, count: 32))
        )
        let serverKeyExchange = try TLS13P256ServerKeyExchange.generate(
            using: FixedEntropy(bytes: ContiguousArray(repeating: 0x22, count: 32))
        )
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let certificateDER = deterministicCertificate()
        let client = try QUICTLSClientHandshake.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            keyExchange: clientKeyExchange,
            certificateValidator: try makeCertificateValidator(
                certificateDER: certificateDER
            ),
            applicationProtocols: [try applicationProtocol()],
            transportParameters: ContiguousArray<UInt8>([0x01, 0x02]).span,
            verificationInstant: instant
        )
        let server = try QUICTLSServerHandshake.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            keyExchange: serverKeyExchange,
            keyExchangeEntropy: FixedEntropy(
                bytes: ContiguousArray(repeating: 0x33, count: 32)
            ),
            certificateDER: certificateDER.span,
            signingKey: TLS13SigningKey(ed25519: signingKey),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [try applicationProtocol()]
                ),
            transportParameters: ContiguousArray<UInt8>([0x03, 0x04]).span
        )
        return Endpoints(client: client, server: server)
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

    private func delegatedCredentialCertificate() throws -> ContiguousArray<UInt8> {
        var tbs = bytes(
            "308181a003020102020101300506032b65703000301e"
                + "170d3234303130313030303030305a"
                + "170d3235303130313030303030305a3000"
                + "302a300506032b6570032100"
        )
        tbs.append(contentsOf: deterministicServerPublicKey())
        tbs.append(contentsOf: bytes(
            "a320301e"
                + "300b0603551d0f040403020780"
                + "300f06092b0601040182da4b2c04020500"
        ))
        let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let signature = try signer.sign(message: tbs.span)
        var certificate = ContiguousArray<UInt8>([0x30, 0x81, 0xCE])
        certificate.append(contentsOf: tbs)
        certificate.append(contentsOf: bytes("300506032b6570034100"))
        certificate.append(contentsOf: signature)
        return certificate
    }

    private func ed25519SubjectPublicKeyInfo(
        publicKey: ContiguousArray<UInt8>
    ) -> ContiguousArray<UInt8> {
        var result: ContiguousArray<UInt8> = [
            0x30, 0x2A,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x21, 0x00,
        ]
        result.append(contentsOf: publicKey)
        return result
    }

    private func makeCertificateValidator(
        certificateDER: ContiguousArray<UInt8>
    ) throws -> RFC5280TLS13ServerCertificateValidator {
        try RFC5280TLS13ServerCertificateValidator(
            trustAnchors: [try X509Certificate(der: certificateDER.span)]
        )
    }

    private func applicationProtocol(
        _ identifier: String = "h3"
    ) throws -> TLS13ApplicationProtocol {
        try TLS13ApplicationProtocol(
            identifier: ContiguousArray<UInt8>(identifier.utf8).span
        )
    }
}

private struct AcceptingEarlyDataReplayProtector:
    TLS13EarlyDataReplayProtecting
{
    func evaluate(
        _ context: TLS13EarlyDataReplayContext
    ) throws -> TLS13EarlyDataReplayDecision {
        _ = context
        return .accept
    }
}
