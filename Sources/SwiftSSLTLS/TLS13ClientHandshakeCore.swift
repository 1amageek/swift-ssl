import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

/// Record-independent TLS 1.3 client state machine.
///
/// The core consumes exactly one complete handshake message per receive call.
/// It owns transcript and key-schedule state, but never frames, seals, opens,
/// retransmits, or reassembles transport bytes.
public struct TLS13ClientHandshakeCore:
    TLS13ClientHandshakeCoreProtocol,
    TLS13ApplicationTrafficSecretManaging,
    ~Copyable,
    Sendable
{
    private enum Phase: Sendable {
        case idle
        case awaitingServerHello
        case awaitingServerFlight
        case established
        case failed
    }

    private let random: OwnedBytes
    private let ephemeralKey: X25519PrivateKey
    private let expectedServerPublicKey: Ed25519PublicKey
    private let verificationInstant: VerificationInstant
    private let cipherSuite: TLSCipherSuite
    private var transcript: TLS13Transcript
    private var resumptionState: TLS13ResumptionState?
    private var resumptionPSK: SecretBytes?
    private var offeredResumption: Bool
    private var resumedHandshake: Bool
    private var handshakeSecrets: TLS13HandshakeSecrets?
    private var applicationSecrets: TLS13ApplicationSecrets?
    private var sawEncryptedExtensions: Bool
    private var sawCertificate: Bool
    private var sawCertificateVerify: Bool
    private var phase: Phase

    public init(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        expectedServerPublicKey: Span<UInt8>,
        verificationInstant: VerificationInstant,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        resumptionState: consuming TLS13ResumptionState? = nil
    ) throws(TLS13HandshakeEngineError) {
        guard random.count == 32 else {
            throw .invalidConfiguration
        }
        guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
            throw .unsupportedCipherSuite(cipherSuite.rawValue)
        }
        let validatedServerPublicKey: Ed25519PublicKey
        do {
            validatedServerPublicKey = try Ed25519PublicKey(bytes: expectedServerPublicKey)
        } catch {
            throw .invalidConfiguration
        }
        do {
            transcript = try TLS13Transcript()
        } catch let error {
            throw .handshake(error)
        }
        self.random = OwnedBytes(copying: random)
        self.ephemeralKey = ephemeralKey
        self.expectedServerPublicKey = validatedServerPublicKey
        self.verificationInstant = verificationInstant
        self.cipherSuite = cipherSuite
        self.resumptionState = resumptionState
        resumptionPSK = nil
        offeredResumption = false
        resumedHandshake = false
        handshakeSecrets = nil
        applicationSecrets = nil
        sawEncryptedExtensions = false
        sawCertificate = false
        sawCertificateVerify = false
        phase = .idle
    }

    public var isEstablished: Bool {
        if case .established = phase { return true }
        return false
    }

    public mutating func start()
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput
    {
        guard case .idle = phase else { throw .invalidState }
        do {
            let keyShare = ephemeralKey.publicKey()
            let clientHello: OwnedBytes
            if var state = resumptionState.take() {
                guard state.cipherSuite == cipherSuite else {
                    throw TLS13HandshakeEngineError.invalidConfiguration
                }
                let psk = try state.consumePSK()
                let ticketAge = try state.obfuscatedTicketAge(at: verificationInstant)
                let identity = try state.withTicketBytes { ticket throws(TLS13PSKError) in
                    try TLS13PSKIdentity(identity: ticket, obfuscatedTicketAge: ticketAge)
                }
                let binderLength = TLS13KeySchedule.hashByteCount(for: cipherSuite)
                let zeroBinder = try TLS13PSKBinder(
                    value: ContiguousArray<UInt8>(repeating: 0, count: binderLength).span
                )
                let zeroExtension = try TLS13PreSharedKeyExtension(
                    identities: ContiguousArray([identity]),
                    binders: ContiguousArray([zeroBinder])
                )
                let zeroHello = try TLS13HandshakeCodec.makeClientHello(
                    random: random.span,
                    keyShare: keyShare.span,
                    cipherSuite: cipherSuite,
                    preSharedKey: zeroExtension
                )
                var binderTranscript = try TLS13Transcript()
                try binderTranscript.append(zeroHello.span)
                let transcriptHash = try binderTranscript.digest(for: cipherSuite)
                let binder = try TLS13PSKBinder.compute(
                    preSharedKey: psk,
                    cipherSuite: cipherSuite,
                    transcriptHash: transcriptHash.span
                )
                let actualBinder = try TLS13PSKBinder(value: binder.span)
                let actualExtension = try TLS13PreSharedKeyExtension(
                    identities: ContiguousArray([identity]),
                    binders: ContiguousArray([actualBinder])
                )
                clientHello = try TLS13HandshakeCodec.makeClientHello(
                    random: random.span,
                    keyShare: keyShare.span,
                    cipherSuite: cipherSuite,
                    preSharedKey: actualExtension
                )
                resumptionPSK = consume psk
                offeredResumption = true
            } else {
                clientHello = try TLS13HandshakeCodec.makeClientHello(
                    random: random.span,
                    keyShare: keyShare.span,
                    cipherSuite: cipherSuite
                )
            }
            return try completeStart(with: clientHello)
        } catch let error {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
    }

    private mutating func completeStart(
        with clientHello: consuming OwnedBytes
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        try appendTranscript(clientHello.span)
        phase = .awaitingServerHello
        return try makeEmission(clientHello, at: .initial)
    }

    public mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        do {
            switch phase {
            case .awaitingServerHello:
                guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
                return try receiveServerHello(message)
            case .awaitingServerFlight:
                guard epoch == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
                return try receiveServerFlightMessage(message)
            case .idle, .established, .failed:
                throw TLS13HandshakeEngineError.invalidState
            }
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
    }

    public mutating func updateApplicationTrafficSecret(
        for endpoint: TLSRole
    ) throws(TLS13HandshakeEngineError) -> TLS13TrafficSecret {
        guard case .established = phase,
              var secrets = applicationSecrets.take() else {
            throw .invalidState
        }
        do {
            switch endpoint {
            case .client: try secrets.updateClientTrafficSecret()
            case .server: try secrets.updateServerTrafficSecret()
            }
            let exported = try secrets.exportTrafficSecret(for: endpoint)
            applicationSecrets = consume secrets
            return exported
        } catch let error as TLS13KeyScheduleError {
            applicationSecrets = consume secrets
            phase = .failed
            throw .keySchedule(error)
        } catch {
            applicationSecrets = consume secrets
            phase = .failed
            throw .malformedInput
        }
    }

    public mutating func makeResumptionState(
        ticket: TLS13NewSessionTicket,
        receivedAt: VerificationInstant
    ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState {
        guard case .established = phase,
              let secrets = applicationSecrets.take() else {
            throw .invalidState
        }
        do {
            let state = try secrets.withResumptionMasterSecret {
                master throws(TLS13ResumptionError) in
                try TLS13ResumptionState(
                    ticket: ticket.ticket.span,
                    ticketNonce: ticket.ticketNonce.span,
                    resumptionMasterSecret: master,
                    cipherSuite: secrets.cipherSuite,
                    issuedAt: receivedAt,
                    lifetime: ticket.lifetime,
                    ageAdd: ticket.ageAdd
                )
            }
            applicationSecrets = consume secrets
            return state
        } catch let error {
            applicationSecrets = consume secrets
            phase = .failed
            throw .resumption(error)
        }
    }

    private mutating func receiveServerHello(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        let serverHello = try engineTry {
            try TLS13HandshakeCodec.parseServerHello(message)
        }
        guard serverHello.cipherSuite == cipherSuite else {
            throw .unsupportedCipherSuite(serverHello.cipherSuite.rawValue)
        }
        guard !serverHello.selectedPreSharedKey || offeredResumption else {
            throw .handshake(.unexpectedMessage(type: TLS13HandshakeCodec.serverHelloType))
        }
        resumedHandshake = offeredResumption && serverHello.selectedPreSharedKey
        try appendTranscript(message)

        let peerKey: X25519PublicKey
        do {
            peerKey = try X25519PublicKey(bytes: serverHello.keyShare.span)
        } catch let error {
            throw .crypto(error)
        }
        let sharedSecret: X25519SharedSecret
        do {
            sharedSecret = try X25519.sharedSecret(
                privateKey: ephemeralKey,
                peerPublicKey: peerKey
            )
        } catch let error {
            throw .crypto(error)
        }
        let transcriptHash = try transcriptDigest()
        let schedule: TLS13KeySchedule
        if resumedHandshake {
            guard let psk = resumptionPSK.take() else { throw .invalidState }
            do {
                schedule = try psk.withBorrowedBytes { bytes in
                    try TLS13KeySchedule(cipherSuite: cipherSuite, preSharedKey: bytes)
                }
            } catch {
                throw mapHandshakeEngineError(error)
            }
        } else {
            resumptionPSK = nil
            schedule = try engineTry {
                try TLS13KeySchedule(
                    cipherSuite: cipherSuite,
                    preSharedKey: ContiguousArray<UInt8>().span
                )
            }
        }
        var sharedBytes = ContiguousArray<UInt8>()
        defer { wipe(&sharedBytes) }
        sharedSecret.withBorrowedBytes { shared in
            sharedBytes.reserveCapacity(shared.count)
            var index = 0
            while index < shared.count {
                sharedBytes.append(shared[index])
                index += 1
            }
        }
        let secrets: TLS13HandshakeSecrets
        do {
            secrets = try schedule.makeHandshakeSecrets(
                ecdheSharedSecret: sharedBytes.span,
                transcriptHash: transcriptHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        let exported: TLS13TrafficSecretPair
        do {
            exported = try secrets.exportTrafficSecrets()
        } catch {
            throw .malformedInput
        }
        handshakeSecrets = consume secrets
        phase = .awaitingServerFlight
        return try makeEmptyOutput(
            actions: [.installTrafficSecrets(epoch: .handshake)],
            handshakeSecrets: exported
        )
    }

    private mutating func receiveServerFlightMessage(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        guard !message.isEmpty else { throw .malformedInput }
        switch message[0] {
        case TLS13HandshakeCodec.encryptedExtensionsType:
            guard !sawEncryptedExtensions, !sawCertificate else { throw .malformedInput }
            _ = try engineTry { try TLS13HandshakeCodec.parseEncryptedExtensions(message) }
            try appendTranscript(message)
            sawEncryptedExtensions = true
            return try makeEmptyOutput()

        case TLS13HandshakeCodec.certificateType:
            guard !resumedHandshake, sawEncryptedExtensions, !sawCertificate else {
                throw .malformedInput
            }
            let certificateBytes = try engineTry {
                try TLS13HandshakeCodec.parseCertificate(message)
            }
            let certificate: X509Certificate
            do {
                certificate = try X509Certificate(der: certificateBytes.span)
                try certificate.verifySignature()
            } catch let error {
                throw .certificate(error)
            }
            guard certificate.validity.contains(verificationInstant) else {
                throw .certificateNotValid
            }
            guard certificate.subjectPublicKeyInfo.isEd25519 else {
                throw .certificateVerificationFailed
            }
            let expected = expectedServerPublicKey
            let matches = certificate.subjectPublicKeyInfo.withPublicKeyBytes { key in
                ConstantTime.equal(key, expected.span)
            }
            guard matches else { throw .certificateKeyMismatch }
            try appendTranscript(message)
            sawCertificate = true
            return try makeEmptyOutput()

        case TLS13HandshakeCodec.certificateVerifyType:
            guard !resumedHandshake, sawCertificate, !sawCertificateVerify else {
                throw .malformedInput
            }
            let certificateVerify = try engineTry {
                try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message)
            }
            guard certificateVerify.signatureScheme == .ed25519 else {
                throw .certificateVerifyFailure
            }
            let hash = try transcriptDigest()
            let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
            guard try verifyCertificateVerify(certificateVerify, signedMessage: signed.span) else {
                throw .certificateVerifyFailure
            }
            try appendTranscript(message)
            sawCertificateVerify = true
            return try makeEmptyOutput()

        case TLS13HandshakeCodec.finishedType:
            guard sawEncryptedExtensions,
                  resumedHandshake || sawCertificateVerify else {
                throw .malformedInput
            }
            return try receiveServerFinished(message)

        default:
            throw .handshake(.unexpectedMessage(type: message[0]))
        }
    }

    private mutating func receiveServerFinished(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        let finished = try engineTry {
            try TLS13HandshakeCodec.parseFinished(
                message,
                hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
            )
        }
        let verificationHash = try transcriptDigest()
        guard let secrets = handshakeSecrets.take() else { throw .invalidState }
        let expected: OwnedBytes
        do {
            expected = try secrets.makeServerFinishedVerifyData(
                transcriptHash: verificationHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        guard ConstantTime.equal(finished.span, expected.span) else {
            throw .certificateVerifyFailure
        }
        try appendTranscript(message)
        let applicationHash = try transcriptDigest()
        let clientFinishedData: OwnedBytes
        do {
            clientFinishedData = try secrets.makeClientFinishedVerifyData(
                transcriptHash: applicationHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        let clientFinished: OwnedBytes
        do {
            clientFinished = try TLS13HandshakeCodec.makeFinished(
                verifyData: clientFinishedData.span
            )
        } catch {
            throw mapHandshakeEngineError(error)
        }
        let derived: TLS13ApplicationSecrets
        do {
            derived = try secrets.makeApplicationSecrets(
                transcriptHash: applicationHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        try appendTranscript(clientFinished.span)
        let exported: TLS13TrafficSecretPair
        do {
            exported = try derived.exportTrafficSecrets()
        } catch {
            throw .malformedInput
        }
        applicationSecrets = consume derived
        phase = .established
        let range: ByteRange
        do {
            range = try ByteRange(offset: 0, count: clientFinished.count)
        } catch let error {
            throw .output(error)
        }
        return try makeOutput(
            bytes: clientFinished,
            actions: [
                .emitHandshakeBytes(epoch: .handshake, bytes: range),
                .installTrafficSecrets(epoch: .application),
                .handshakeComplete,
            ],
            applicationSecrets: exported
        )
    }

    private func verifyCertificateVerify(
        _ value: TLS13CertificateVerify,
        signedMessage: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> Bool {
        do {
            return try Ed25519.verify(
                signature: value.signature.span,
                message: signedMessage,
                using: expectedServerPublicKey
            )
        } catch {
            throw .certificateVerifyFailure
        }
    }

    private mutating func appendTranscript(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) {
        do {
            try transcript.append(message)
        } catch let error {
            throw .handshake(error)
        }
    }

    private borrowing func transcriptDigest()
        throws(TLS13HandshakeEngineError) -> OwnedBytes
    {
        do {
            return try transcript.digest(for: cipherSuite)
        } catch let error {
            throw .handshake(error)
        }
    }

    private func makeEmission(
        _ message: OwnedBytes,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        let range: ByteRange
        do {
            range = try ByteRange(offset: 0, count: message.count)
        } catch let error {
            throw .output(error)
        }
        return try makeOutput(
            bytes: message,
            actions: [.emitHandshakeBytes(epoch: epoch, bytes: range)]
        )
    }

    private func makeEmptyOutput(
        actions: ContiguousArray<TLS13HandshakeCoreAction> = [],
        handshakeSecrets: consuming TLS13TrafficSecretPair? = nil
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        try makeOutput(
            bytes: OwnedBytes(),
            actions: actions,
            handshakeSecrets: handshakeSecrets
        )
    }

    private func makeOutput(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<TLS13HandshakeCoreAction>,
        handshakeSecrets: consuming TLS13TrafficSecretPair? = nil,
        applicationSecrets: consuming TLS13TrafficSecretPair? = nil
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        do {
            return try TLS13HandshakeCoreOutput(
                bytes: bytes,
                actions: actions,
                handshakeSecrets: handshakeSecrets,
                applicationSecrets: applicationSecrets
            )
        } catch let error {
            switch error {
            case .byteRange(let byteError): throw .output(byteError)
            case .duplicateTrafficSecrets, .missingTrafficSecrets,
                 .unreferencedTrafficSecrets: throw .invalidState
            }
        }
    }
}
