import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

/// Record-independent TLS 1.3 server state machine.
///
/// The core owns authentication, transcript, and key-schedule semantics. A
/// transport adapter owns message framing, reliability, and encryption.
public struct TLS13ServerHandshakeCore:
    TLS13ServerHandshakeCoreProtocol,
    TLS13ApplicationTrafficSecretManaging,
    ~Copyable,
    Sendable
{
    private enum Phase: Sendable {
        case awaitingClientHello
        case awaitingClientFinished
        case established
        case failed
    }

    private let random: OwnedBytes
    private let ephemeralKey: X25519PrivateKey
    private let certificate: CertificateBytes
    private let signingKey: TLS13SigningKey
    private let verificationInstant: VerificationInstant
    private let resumptionIdentity: OwnedBytes?
    private let resumptionPSK: SecretBytes?
    private let resumptionIssuedAt: VerificationInstant?
    private let resumptionLifetime: UInt32?
    private let resumptionAgeAdd: UInt32?
    private let resumptionAgeToleranceMilliseconds: UInt32
    private var cipherSuite: TLSCipherSuite
    private var transcript: TLS13Transcript
    private var resumedHandshake: Bool
    private var handshakeSecrets: TLS13HandshakeSecrets?
    private var applicationSecrets: TLS13ApplicationSecrets?
    private var phase: Phase

    public init(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        certificateDER: Span<UInt8>,
        signingKey: consuming TLS13SigningKey,
        verificationInstant: VerificationInstant,
        resumptionIdentity: Span<UInt8>? = nil,
        resumptionPSK: Span<UInt8>? = nil,
        resumptionIssuedAt: VerificationInstant? = nil,
        resumptionLifetime: UInt32? = nil,
        resumptionAgeAdd: UInt32? = nil,
        resumptionAgeToleranceMilliseconds: UInt32 = 10_000
    ) throws(TLS13HandshakeEngineError) {
        guard random.count == 32 else { throw .invalidConfiguration }
        let parsed: X509Certificate
        do {
            parsed = try X509Certificate(der: certificateDER)
        } catch let error {
            throw .certificate(error)
        }
        guard parsed.validity.contains(verificationInstant) else {
            throw .certificateNotValid
        }
        guard parsed.subjectPublicKeyInfo.isEd25519 else {
            throw .invalidConfiguration
        }
        guard (resumptionIdentity == nil) == (resumptionPSK == nil) else {
            throw .invalidConfiguration
        }
        let hasAgeMetadata = resumptionIssuedAt != nil
            && resumptionLifetime != nil
            && resumptionAgeAdd != nil
        guard (resumptionIdentity == nil) == !hasAgeMetadata else {
            throw .invalidConfiguration
        }
        if let lifetime = resumptionLifetime {
            guard lifetime > 0 else { throw .invalidConfiguration }
        }
        guard resumptionAgeToleranceMilliseconds <= 60_000 else {
            throw .invalidConfiguration
        }
        let configuredIdentity: OwnedBytes?
        let configuredPSK: SecretBytes?
        if let identity = resumptionIdentity, let psk = resumptionPSK {
            guard !identity.isEmpty, psk.count <= 64 else { throw .invalidConfiguration }
            configuredIdentity = OwnedBytes(copying: identity)
            do {
                configuredPSK = try SecretBytes(copying: psk)
            } catch {
                throw .invalidConfiguration
            }
        } else {
            configuredIdentity = nil
            configuredPSK = nil
        }
        let publicBytes: ContiguousArray<UInt8>
        do {
            publicBytes = try signingKey.publicKeyBytes()
        } catch let error {
            throw .crypto(error)
        }
        let publicKey = OwnedBytes(consuming: publicBytes)
        let keyMatches = parsed.subjectPublicKeyInfo.withPublicKeyBytes { key in
            ConstantTime.equal(key, publicKey.span)
        }
        guard keyMatches else { throw .certificateKeyMismatch }
        do {
            transcript = try TLS13Transcript()
        } catch let error {
            throw .handshake(error)
        }
        self.random = OwnedBytes(copying: random)
        self.ephemeralKey = ephemeralKey
        self.certificate = CertificateBytes(copying: certificateDER)
        self.signingKey = signingKey
        self.verificationInstant = verificationInstant
        self.resumptionIdentity = configuredIdentity
        self.resumptionPSK = configuredPSK
        self.resumptionIssuedAt = resumptionIssuedAt
        self.resumptionLifetime = resumptionLifetime
        self.resumptionAgeAdd = resumptionAgeAdd
        self.resumptionAgeToleranceMilliseconds = resumptionAgeToleranceMilliseconds
        cipherSuite = .aes128GCM_SHA256
        resumedHandshake = false
        handshakeSecrets = nil
        applicationSecrets = nil
        phase = .awaitingClientHello
    }

    public var isEstablished: Bool {
        if case .established = phase { return true }
        return false
    }

    public mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        do {
            switch phase {
            case .awaitingClientHello:
                guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
                return try receiveClientHello(message)
            case .awaitingClientFinished:
                guard epoch == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
                return try receiveClientFinished(message)
            case .established, .failed:
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

    private mutating func receiveClientHello(
        _ encodedClientHello: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        let clientHello = try engineTry {
            try TLS13HandshakeCodec.parseClientHello(encodedClientHello)
        }
        cipherSuite = clientHello.cipherSuite
        resumedHandshake = try acceptResumption(
            clientHello: clientHello,
            encodedClientHello: encodedClientHello
        )
        try appendTranscript(encodedClientHello)

        let clientPublicKey: X25519PublicKey
        do {
            clientPublicKey = try X25519PublicKey(bytes: clientHello.keyShare.span)
        } catch let error {
            throw .crypto(error)
        }
        let sharedSecret: X25519SharedSecret
        do {
            sharedSecret = try X25519.sharedSecret(
                privateKey: ephemeralKey,
                peerPublicKey: clientPublicKey
            )
        } catch let error {
            throw .crypto(error)
        }
        let serverHello = try engineTry {
            try TLS13HandshakeCodec.makeServerHello(
                random: random.span,
                keyShare: ephemeralKey.publicKey().span,
                cipherSuite: cipherSuite,
                selectedPreSharedKey: resumedHandshake
            )
        }
        try appendTranscript(serverHello.span)
        let helloHash = try transcriptDigest()
        let schedule: TLS13KeySchedule
        if resumedHandshake {
            guard resumptionPSK != nil else { throw .invalidState }
            do {
                schedule = try resumptionPSK!.withBorrowedBytes { bytes in
                    try TLS13KeySchedule(cipherSuite: cipherSuite, preSharedKey: bytes)
                }
            } catch {
                throw mapHandshakeEngineError(error)
            }
        } else {
            schedule = try engineTry {
                try TLS13KeySchedule(
                    cipherSuite: cipherSuite,
                    preSharedKey: ContiguousArray<UInt8>().span
                )
            }
        }
        var sharedBytes = ContiguousArray<UInt8>()
        defer { wipe(&sharedBytes) }
        sharedSecret.withBorrowedBytes { bytes in
            sharedBytes.reserveCapacity(bytes.count)
            var index = 0
            while index < bytes.count {
                sharedBytes.append(bytes[index])
                index += 1
            }
        }
        let secrets: TLS13HandshakeSecrets
        do {
            secrets = try schedule.makeHandshakeSecrets(
                ecdheSharedSecret: sharedBytes.span,
                transcriptHash: helloHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        let handshakeExport: TLS13TrafficSecretPair
        do {
            handshakeExport = try secrets.exportTrafficSecrets()
        } catch {
            throw .malformedInput
        }
        handshakeSecrets = consume secrets

        let serverFlight = try makeServerFlightMessages()
        let applicationHash = try transcriptDigest()
        guard handshakeSecrets != nil else { throw .invalidState }
        let derived: TLS13ApplicationSecrets
        do {
            derived = try handshakeSecrets!.makeApplicationSecretsCopy(
                transcriptHash: applicationHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        let applicationExport: TLS13TrafficSecretPair
        do {
            applicationExport = try derived.exportTrafficSecrets()
        } catch {
            throw .malformedInput
        }
        applicationSecrets = consume derived
        phase = .awaitingClientFinished
        return try makeServerFlightOutput(
            serverHello: serverHello,
            encryptedFlight: serverFlight,
            handshakeSecrets: handshakeExport,
            applicationSecrets: applicationExport
        )
    }

    private mutating func makeServerFlightMessages()
        throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes>
    {
        guard handshakeSecrets != nil else { throw .invalidState }
        var messages = ContiguousArray<OwnedBytes>()
        let encryptedExtensions = try engineTry {
            try TLS13HandshakeCodec.makeEncryptedExtensions()
        }
        try appendTranscript(encryptedExtensions.span)
        messages.append(encryptedExtensions)
        if !resumedHandshake {
            let certificateMessage = try engineTry {
                try TLS13HandshakeCodec.makeCertificate(certificateDER: certificate.span)
            }
            try appendTranscript(certificateMessage.span)
            messages.append(certificateMessage)
            let hash = try transcriptDigest()
            let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
            let wireSignature = try engineTry { try signingKey.sign(message: signed.span) }
            let certificateVerify = try makeCertificateVerifyMessage(
                signatureScheme: signingKey.signatureScheme,
                signature: wireSignature
            )
            try appendTranscript(certificateVerify.span)
            messages.append(certificateVerify)
        }
        let finishedHash = try transcriptDigest()
        let verifyData: OwnedBytes
        do {
            verifyData = try handshakeSecrets!.makeServerFinishedVerifyData(
                transcriptHash: finishedHash.span
            )
        } catch let error {
            throw .keySchedule(error)
        }
        let finishedMessage: OwnedBytes
        do {
            finishedMessage = try TLS13HandshakeCodec.makeFinished(
                verifyData: verifyData.span
            )
        } catch {
            throw mapHandshakeEngineError(error)
        }
        try appendTranscript(finishedMessage.span)
        messages.append(finishedMessage)
        return messages
    }

    private mutating func receiveClientFinished(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        guard !message.isEmpty,
              message[0] == TLS13HandshakeCodec.finishedType else {
            throw .malformedInput
        }
        let finished = try engineTry {
            try TLS13HandshakeCodec.parseFinished(
                message,
                hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
            )
        }
        let hash = try transcriptDigest()
        guard let secrets = handshakeSecrets.take() else { throw .invalidState }
        let expected: OwnedBytes
        do {
            expected = try secrets.makeClientFinishedVerifyData(transcriptHash: hash.span)
        } catch let error {
            throw .keySchedule(error)
        }
        guard ConstantTime.equal(finished.span, expected.span) else {
            throw .certificateVerifyFailure
        }
        try appendTranscript(message)
        phase = .established
        return try makeOutput(
            bytes: OwnedBytes(),
            actions: [.handshakeComplete, .handshakeConfirmed]
        )
    }

    private func acceptResumption(
        clientHello: TLS13ClientHello,
        encodedClientHello: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> Bool {
        guard let configuredIdentity = resumptionIdentity,
              resumptionPSK != nil,
              let issuedAt = resumptionIssuedAt,
              let lifetime = resumptionLifetime,
              let ageAdd = resumptionAgeAdd else {
            return false
        }
        return try verifyCoreResumption(
            clientHello: clientHello,
            encodedClientHello: encodedClientHello,
            configuredIdentity: configuredIdentity,
            preSharedKey: resumptionPSK!,
            verificationInstant: verificationInstant,
            issuedAt: issuedAt,
            lifetime: lifetime,
            ageAdd: ageAdd,
            toleranceMilliseconds: resumptionAgeToleranceMilliseconds
        )
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

    private func makeServerFlightOutput(
        serverHello: OwnedBytes,
        encryptedFlight: ContiguousArray<OwnedBytes>,
        handshakeSecrets: consuming TLS13TrafficSecretPair,
        applicationSecrets: consuming TLS13TrafficSecretPair
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
        var storage = ContiguousArray<UInt8>()
        var messagesByteCount = 0
        for message in encryptedFlight { messagesByteCount += message.count }
        storage.reserveCapacity(serverHello.count + messagesByteCount)
        append(serverHello.span, to: &storage)
        for message in encryptedFlight { append(message.span, to: &storage) }
        let helloRange: ByteRange
        let flightRange: ByteRange
        do {
            helloRange = try ByteRange(offset: 0, count: serverHello.count)
            flightRange = try ByteRange(offset: serverHello.count, count: messagesByteCount)
        } catch let error {
            throw .output(error)
        }
        return try makeOutput(
            bytes: OwnedBytes(consuming: storage),
            actions: [
                .emitHandshakeBytes(epoch: .initial, bytes: helloRange),
                .installTrafficSecrets(epoch: .handshake),
                .emitHandshakeBytes(epoch: .handshake, bytes: flightRange),
                .installTrafficSecrets(epoch: .application),
            ],
            handshakeSecrets: handshakeSecrets,
            applicationSecrets: applicationSecrets
        )
    }

    private func append(
        _ source: Span<UInt8>,
        to destination: inout ContiguousArray<UInt8>
    ) {
        var index = 0
        while index < source.count {
            destination.append(source[index])
            index += 1
        }
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

private func verifyCoreResumption(
    clientHello: TLS13ClientHello,
    encodedClientHello: Span<UInt8>,
    configuredIdentity: OwnedBytes,
    preSharedKey: borrowing SecretBytes,
    verificationInstant: VerificationInstant,
    issuedAt: VerificationInstant,
    lifetime: UInt32,
    ageAdd: UInt32,
    toleranceMilliseconds: UInt32
) throws(TLS13HandshakeEngineError) -> Bool {
    guard let offered = clientHello.preSharedKey,
          offered.identities.count == 1,
          offered.binders.count == 1 else {
        return false
    }
    let identity = offered.identities[0]
    let offeredBinder = offered.binders[0].value
    guard ConstantTime.equal(identity.identity.span, configuredIdentity.span),
          let expectedAge = expectedObfuscatedTicketAge(
              at: verificationInstant,
              issuedAt: issuedAt,
              lifetime: lifetime,
              ageAdd: ageAdd
          ),
          ticketAgeWithinTolerance(
              offered: identity.obfuscatedTicketAge,
              expected: expectedAge,
              toleranceMilliseconds: toleranceMilliseconds
          ) else {
        return false
    }
    let canonical = try engineTry {
        try TLS13HandshakeCodec.makeClientHello(
            random: clientHello.random.span,
            keyShare: clientHello.keyShare.span,
            cipherSuite: clientHello.cipherSuite,
            preSharedKey: offered
        )
    }
    guard ConstantTime.equal(canonical.span, encodedClientHello) else {
        return false
    }
    var zeroBinders = ContiguousArray<TLS13PSKBinder>()
    var binderIndex = 0
    while binderIndex < offered.binders.count {
        let count = offered.binders[binderIndex].value.count
        let zero = ContiguousArray<UInt8>(repeating: 0, count: count)
        do {
            zeroBinders.append(try TLS13PSKBinder(value: zero.span))
        } catch let error {
            throw .preSharedKey(error)
        }
        binderIndex += 1
    }
    let zeroExtension: TLS13PreSharedKeyExtension
    do {
        zeroExtension = try TLS13PreSharedKeyExtension(
            identities: ContiguousArray(offered.identities),
            binders: zeroBinders
        )
    } catch let error {
        throw .preSharedKey(error)
    }
    let zeroHello = try engineTry {
        try TLS13HandshakeCodec.makeClientHello(
            random: clientHello.random.span,
            keyShare: clientHello.keyShare.span,
            cipherSuite: clientHello.cipherSuite,
            preSharedKey: zeroExtension
        )
    }
    do {
        var binderTranscript = try TLS13Transcript()
        try binderTranscript.append(zeroHello.span)
        let hash = try binderTranscript.digest(for: clientHello.cipherSuite)
        return try TLS13PSKBinder.verify(
            preSharedKey: preSharedKey,
            cipherSuite: clientHello.cipherSuite,
            transcriptHash: hash.span,
            binder: offeredBinder.span
        )
    } catch let error as TLS13PSKError {
        throw .preSharedKey(error)
    } catch {
        throw .preSharedKey(.derivationFailed)
    }
}
