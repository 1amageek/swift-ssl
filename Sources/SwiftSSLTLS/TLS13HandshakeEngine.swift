import SwiftSSLCore
import SwiftSSLASN1
import SwiftSSLCrypto
import SwiftSSLX509

/// A synchronous TLS 1.3 client handshake for the supported X25519/Ed25519
/// profile. Transport I/O, buffering, and trust-store lookup remain outside
/// the engine; each step consumes complete TLS records and returns one owned
/// output batch.
public struct TLS13ClientHandshake: ~Copyable, Sendable {
    private enum Phase: Sendable {
        case idle
        case awaitingServerHello
        case established
        case failed
    }

    private let random: OwnedBytes
    private let ephemeralKey: X25519PrivateKey
    private let expectedServerPublicKey: OwnedBytes
    private let verificationInstant: VerificationInstant
    private let cipherSuite: TLSCipherSuite
    private var transcript: TLS13Transcript
    private var handshakeSecrets: TLS13HandshakeSecrets?
    private var handshakeRead: TLS13RecordProtector?
    private var handshakeWrite: TLS13RecordProtector?
    private var applicationSecrets: TLS13ApplicationSecrets?
    private var applicationRead: TLS13RecordProtector?
    private var applicationWrite: TLS13RecordProtector?
    private var phase: Phase

    public init(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        expectedServerPublicKey: Span<UInt8>,
        verificationInstant: VerificationInstant,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256
    ) throws(TLS13HandshakeEngineError) {
        guard random.count == 32, expectedServerPublicKey.count == 32 else {
            throw .invalidConfiguration
        }
        guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
            throw .unsupportedCipherSuite(cipherSuite.rawValue)
        }
        do {
            transcript = try TLS13Transcript()
        } catch let error {
            throw .handshake(error)
        }
        self.random = OwnedBytes(copying: random)
        self.ephemeralKey = ephemeralKey
        self.expectedServerPublicKey = OwnedBytes(copying: expectedServerPublicKey)
        self.verificationInstant = verificationInstant
        self.cipherSuite = cipherSuite
        handshakeSecrets = nil
        handshakeRead = nil
        handshakeWrite = nil
        applicationSecrets = nil
        applicationRead = nil
        applicationWrite = nil
        phase = .idle
    }

    public var isEstablished: Bool {
        if case .established = phase { return true }
        return false
    }

    public mutating func start() throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .idle = phase else { throw .invalidState }
        let keyShare = ephemeralKey.publicKey()
        let clientHello: OwnedBytes
        do {
            clientHello = try TLS13HandshakeCodec.makeClientHello(
                random: random.span,
                keyShare: keyShare.span,
                cipherSuite: cipherSuite
            )
            try transcript.append(clientHello.span)
        } catch let error {
            phase = .failed
            throw .handshake(error)
        }
        phase = .awaitingServerHello
        do {
            let record = try TLS13HandshakeWire.makePlaintextRecord(clientHello.span)
            return try TLS13HandshakeWire.makeOutput(records: ContiguousArray([record]), completed: false)
        } catch let error {
            phase = .failed
            throw error
        }
    }

    /// Seals application data after the handshake using the installed 1-RTT key.
    /// The caller's input is borrowed directly by the AEAD operation.
    public mutating func sendApplicationData(
        _ content: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        guard content.count <= TLS13RecordProtector.maximumPlaintextByteCount else {
            throw .record(.invalidContentLength(actual: content.count))
        }
        guard var protector = applicationWrite.take() else { throw .invalidState }
        let record: OwnedBytes
        do {
            record = try TLS13HandshakeWire.seal(
                content: content,
                contentType: .applicationData,
                with: &protector
            )
        } catch let error {
            applicationWrite = consume protector
            throw error
        }
        applicationWrite = consume protector
        return try TLS13HandshakeWire.makeOutput(
            records: ContiguousArray([record]),
            completed: false
        )
    }

    /// Opens one 1-RTT application record and returns owned plaintext.
    public mutating func receiveApplicationRecord(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        guard case .established = phase else { throw .invalidState }
        let records = try TLS13HandshakeWire.splitRecords(input)
        guard records.count == 1 else { throw .malformedInput }
        guard var protector = applicationRead.take() else { throw .invalidState }
        let record = records[0]
        var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
        var destination = plaintext.mutableSpan
        let contentType: TLS13ContentType
        do {
            contentType = try protector.open(record: record.span, into: &destination)
        } catch let error {
            applicationRead = consume protector
            throw .record(error)
        }
        let count = protector.lastOpenedByteCount
        let result = OwnedBytes(copying: destination.span.extracting(0..<count))
        applicationRead = consume protector
        guard contentType == .applicationData else { throw .malformedInput }
        return result
    }

    /// Sends a post-handshake KeyUpdate under the current write key and then
    /// installs the next write traffic secret for subsequent records.
    public mutating func requestKeyUpdate(
        requestPeerUpdate: Bool = false
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        guard var secrets = applicationSecrets.take(),
              var oldProtector = applicationWrite.take() else {
            throw .invalidState
        }
        let message: OwnedBytes
        do {
            message = try TLS13HandshakeCodec.makeKeyUpdate(
                requestUpdate: requestPeerUpdate
            )
        } catch let error {
            applicationSecrets = consume secrets
            applicationWrite = consume oldProtector
            throw .handshake(error)
        }
        let record: OwnedBytes
        do {
            record = try TLS13HandshakeWire.seal(message, with: &oldProtector)
        } catch let error {
            applicationSecrets = consume secrets
            applicationWrite = consume oldProtector
            throw error
        }
        do {
            try secrets.updateClientTrafficSecret()
            let newProtector = try secrets.withClientTrafficSecret { secret throws(TLS13RecordError) in
                try TLS13RecordProtector(cipherSuite: secrets.cipherSuite, trafficSecret: secret)
            }
            applicationSecrets = consume secrets
            applicationWrite = consume newProtector
        } catch {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
        return try TLS13HandshakeWire.makeOutput(
            records: ContiguousArray([record]),
            completed: false
        )
    }

    /// Receives a post-handshake KeyUpdate. If the peer requests an update,
    /// the returned output contains the required response record.
    public mutating func receivePostHandshakeRecord(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        do {
            let records = try TLS13HandshakeWire.splitRecords(input)
            guard records.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            guard var protector = applicationRead.take() else { throw TLS13HandshakeEngineError.invalidState }
            let record = records[0]
            var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
            var destination = plaintext.mutableSpan
            let contentType: TLS13ContentType
            do {
                contentType = try protector.open(record: record.span, into: &destination)
            } catch {
                throw mapHandshakeEngineError(error)
            }
            guard contentType == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
            let count = protector.lastOpenedByteCount
            applicationRead = consume protector
            let messages = try engineTry {
                try TLS13HandshakeCodec.splitMessages(destination.span.extracting(0..<count))
            }
            guard messages.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            let requestPeerUpdate = try parseKeyUpdateMessage(messages[0])
            guard var secrets = applicationSecrets.take() else { throw TLS13HandshakeEngineError.invalidState }
            try secrets.updateServerTrafficSecret()
            let newProtector = try secrets.withServerTrafficSecret { secret throws(TLS13RecordError) in
                try TLS13RecordProtector(cipherSuite: secrets.cipherSuite, trafficSecret: secret)
            }
            applicationSecrets = consume secrets
            applicationRead = consume newProtector
            if requestPeerUpdate {
                return try requestKeyUpdate(requestPeerUpdate: false)
            }
            return try TLS13HandshakeWire.makeOutput(records: ContiguousArray(), completed: false)
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
    }

    public mutating func receive(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        do {
            switch phase {
            case .awaitingServerHello:
                return try receiveServerFlight(input)
            default:
                throw TLS13HandshakeEngineError.invalidState
            }
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch {
            phase = .failed
            throw .malformedInput
        }
    }

    private mutating func receiveServerFlight(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        let records = try TLS13HandshakeWire.splitRecords(input)
        guard !records.isEmpty else { throw .malformedInput }
        let first = records[0]
        guard first[0] == TLS13HandshakeWire.handshakeContentType else {
            throw .malformedInput
        }
        let serverHello = try engineTry {
            try TLS13HandshakeCodec.parseServerHello(first.span.extracting(5..<first.count))
        }
        guard serverHello.cipherSuite == cipherSuite else {
            throw .unsupportedCipherSuite(serverHello.cipherSuite.rawValue)
        }
        try appendTranscript(first.span.extracting(5..<first.count))

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
        let transcriptHash = try transcriptDigest(for: serverHello.cipherSuite)
        let emptyPSK = ContiguousArray<UInt8>()
        do {
            let schedule = try engineTry { try TLS13KeySchedule(
                cipherSuite: serverHello.cipherSuite,
                preSharedKey: emptyPSK.span
            ) }
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
            let secrets = try engineTry {
                try schedule.makeHandshakeSecrets(
                    ecdheSharedSecret: sharedBytes.span,
                    transcriptHash: transcriptHash.span
                )
            }
            let readProtector = try engineTry { try secrets.withServerTrafficSecret { secret in
                try TLS13RecordProtector(
                    cipherSuite: serverHello.cipherSuite,
                    trafficSecret: secret
                )
            } }
            let writeProtector = try engineTry { try secrets.withClientTrafficSecret { secret in
                try TLS13RecordProtector(
                    cipherSuite: serverHello.cipherSuite,
                    trafficSecret: secret
                )
            } }
            handshakeSecrets = consume secrets
            handshakeRead = consume readProtector
            handshakeWrite = consume writeProtector
        } catch {
            throw mapHandshakeEngineError(error)
        }

        var encryptedMessages = ContiguousArray<OwnedBytes>()
        var recordIndex = 1
        while recordIndex < records.count {
            encryptedMessages.append(contentsOf: try openHandshakeRecord(records[recordIndex]))
            recordIndex += 1
        }
        try processServerMessages(encryptedMessages)
        return try makeClientFinishedOutput()
    }

    private mutating func processServerMessages(
        _ messages: ContiguousArray<OwnedBytes>
    ) throws(TLS13HandshakeEngineError) {
        var sawEncryptedExtensions = false
        var sawCertificate = false
        var sawCertificateVerify = false
        var sawFinished = false
        for message in messages {
            guard !message.isEmpty else { throw .malformedInput }
            switch message[0] {
            case TLS13HandshakeCodec.encryptedExtensionsType:
                guard !sawEncryptedExtensions, !sawCertificate else { throw .malformedInput }
                _ = try engineTry { try TLS13HandshakeCodec.parseEncryptedExtensions(message.span) }
                try appendTranscript(message.span)
                sawEncryptedExtensions = true
            case TLS13HandshakeCodec.certificateType:
                guard sawEncryptedExtensions, !sawCertificate else { throw .malformedInput }
                let certificateBytes = try engineTry { try TLS13HandshakeCodec.parseCertificate(message.span) }
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
                guard certificate.subjectPublicKeyInfo.algorithm == .ed25519 else {
                    throw .certificateVerificationFailed
                }
                let expected = expectedServerPublicKey
                let matches = certificate.subjectPublicKeyInfo.withPublicKeyBytes { key in
                    ConstantTime.equal(key, expected.span)
                }
                guard matches else { throw .certificateKeyMismatch }
                try appendTranscript(message.span)
                sawCertificate = true
            case TLS13HandshakeCodec.certificateVerifyType:
                guard sawCertificate, !sawCertificateVerify else { throw .malformedInput }
                let signature = try engineTry { try TLS13HandshakeCodec.parseCertificateVerify(message.span) }
                let hash = try transcriptDigest(for: cipherSuite)
                let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
                let verified = try engineTry {
                    try Ed25519.verify(
                        signature: signature.span,
                        message: signed.span,
                        publicKey: expectedServerPublicKey.span
                    )
                }
                guard verified else { throw .certificateVerifyFailure }
                try appendTranscript(message.span)
                sawCertificateVerify = true
            case TLS13HandshakeCodec.finishedType:
                guard sawCertificateVerify, !sawFinished else { throw .malformedInput }
                let hashByteCount = TLS13KeySchedule.hashByteCount(for: cipherSuite)
                let finished = try engineTry { try TLS13HandshakeCodec.parseFinished(message.span, hashByteCount: hashByteCount) }
                let hash = try transcriptDigest(for: cipherSuite)
                guard handshakeSecrets != nil else { throw .invalidState }
                let expected: OwnedBytes
                do {
                    expected = try handshakeSecrets!.makeServerFinishedVerifyData(transcriptHash: hash.span)
                } catch let error {
                    throw .keySchedule(error)
                }
                guard ConstantTime.equal(finished.span, expected.span) else {
                    throw .certificateVerifyFailure
                }
                try appendTranscript(message.span)
                sawFinished = true
            default:
                throw .handshake(.unexpectedMessage(type: message[0]))
            }
        }
        guard sawEncryptedExtensions, sawCertificate, sawCertificateVerify, sawFinished else {
            throw .malformedInput
        }
    }

    private mutating func makeClientFinishedOutput() throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard let secrets = handshakeSecrets.take(),
              var writeProtector = handshakeWrite.take() else {
            throw .invalidState
        }
        let hash = try transcriptDigest(for: cipherSuite)
        let finished = try engineTry { try secrets.makeClientFinishedVerifyData(transcriptHash: hash.span) }
        let message = try engineTry { try TLS13HandshakeCodec.makeFinished(verifyData: finished.span) }
        try appendTranscript(message.span)
        let record = try TLS13HandshakeWire.seal(
            message,
            with: &writeProtector
        )
        let applicationSecrets: TLS13ApplicationSecrets
        do {
            applicationSecrets = try secrets.makeApplicationSecrets(transcriptHash: hash.span)
        } catch let error {
            throw .keySchedule(error)
        }
        var readApplication: TLS13RecordProtector? = nil
        var writeApplication: TLS13RecordProtector? = nil
        do {
            readApplication = try applicationSecrets.withServerTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            }
            writeApplication = try applicationSecrets.withClientTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            }
        } catch {
            if let error = error as? TLS13RecordError {
                throw .record(error)
            }
            throw .malformedInput
        }
        handshakeSecrets = nil
        guard let readApplication, let writeApplication else { throw .malformedInput }
        handshakeWrite = consume writeProtector
        self.applicationSecrets = consume applicationSecrets
        applicationRead = consume readApplication
        applicationWrite = consume writeApplication
        phase = .established
        return try TLS13HandshakeWire.makeOutput(records: ContiguousArray([record]), completed: true)
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

    private borrowing func transcriptDigest(
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        do {
            return try transcript.digest(for: cipherSuite)
        } catch let error {
            throw .handshake(error)
        }
    }

    private mutating func openHandshakeRecord(
        _ record: OwnedBytes
    ) throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes> {
        guard record.count >= TLS13RecordProtector.recordHeaderByteCount else {
            throw .malformedInput
        }
        guard var protector = handshakeRead.take() else { throw .invalidState }
        var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
        var output = plaintext.mutableSpan
        let contentType: TLS13ContentType
        do {
            contentType = try protector.open(record: record.span, into: &output)
        } catch {
            if let error = error as? TLS13RecordError {
                throw .record(error)
            }
            throw .malformedInput
        }
        guard contentType == .handshake else { throw .malformedInput }
        let count = protector.lastOpenedByteCount
        handshakeRead = consume protector
        do {
            let messages = try engineTry { try TLS13HandshakeCodec.splitMessages(output.span.extracting(0..<count)) }
            return messages
        } catch let error {
            throw error
        }
    }
}

/// A synchronous TLS 1.3 server handshake using an Ed25519 certificate and
/// X25519 key exchange. The application supplies the certificate and signing
/// key; trust policy for clients is intentionally outside this engine.
public struct TLS13ServerHandshake: ~Copyable, Sendable {
    private enum Phase: Sendable {
        case awaitingClientHello
        case awaitingClientFinished
        case established
        case failed
    }

    private let random: OwnedBytes
    private let ephemeralKey: X25519PrivateKey
    private let certificate: CertificateBytes
    private let signingKey: Ed25519PrivateKey
    private let verificationInstant: VerificationInstant
    private var cipherSuite: TLSCipherSuite
    private var transcript: TLS13Transcript
    private var handshakeSecrets: TLS13HandshakeSecrets?
    private var handshakeRead: TLS13RecordProtector?
    private var handshakeWrite: TLS13RecordProtector?
    private var applicationSecrets: TLS13ApplicationSecrets?
    private var applicationRead: TLS13RecordProtector?
    private var applicationWrite: TLS13RecordProtector?
    private var phase: Phase

    public init(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        certificateDER: Span<UInt8>,
        signingKey: consuming Ed25519PrivateKey,
        verificationInstant: VerificationInstant
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
        guard parsed.subjectPublicKeyInfo.algorithm == .ed25519 else {
            throw .invalidConfiguration
        }
        let signerPublicKeyBytes: ContiguousArray<UInt8>
        do {
            signerPublicKeyBytes = try signingKey.publicKey()
        } catch let error {
            throw .crypto(error)
        }
        let signerPublicKey = OwnedBytes(consuming: signerPublicKeyBytes)
        let certificateKeyMatches = parsed.subjectPublicKeyInfo.withPublicKeyBytes { key in
            ConstantTime.equal(key, signerPublicKey.span)
        }
        guard certificateKeyMatches else { throw .certificateKeyMismatch }
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
        self.cipherSuite = .aes128GCM_SHA256
        handshakeSecrets = nil
        handshakeRead = nil
        handshakeWrite = nil
        applicationSecrets = nil
        applicationRead = nil
        applicationWrite = nil
        phase = .awaitingClientHello
    }

    public var isEstablished: Bool {
        if case .established = phase { return true }
        return false
    }

    public mutating func receive(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        do {
            switch phase {
            case .awaitingClientHello:
                return try receiveClientHello(input)
            case .awaitingClientFinished:
                return try receiveClientFinished(input)
            default:
                throw TLS13HandshakeEngineError.invalidState
            }
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch {
            phase = .failed
            throw .malformedInput
        }
    }

    public mutating func sendApplicationData(
        _ content: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        guard content.count <= TLS13RecordProtector.maximumPlaintextByteCount else {
            throw .record(.invalidContentLength(actual: content.count))
        }
        guard var protector = applicationWrite.take() else { throw .invalidState }
        let record: OwnedBytes
        do {
            record = try TLS13HandshakeWire.seal(
                content: content,
                contentType: .applicationData,
                with: &protector
            )
        } catch let error {
            applicationWrite = consume protector
            throw error
        }
        applicationWrite = consume protector
        return try TLS13HandshakeWire.makeOutput(
            records: ContiguousArray([record]),
            completed: false
        )
    }

    public mutating func receiveApplicationRecord(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        guard case .established = phase else { throw .invalidState }
        let records = try TLS13HandshakeWire.splitRecords(input)
        guard records.count == 1 else { throw .malformedInput }
        guard var protector = applicationRead.take() else { throw .invalidState }
        let record = records[0]
        var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
        var destination = plaintext.mutableSpan
        let contentType: TLS13ContentType
        do {
            contentType = try protector.open(record: record.span, into: &destination)
        } catch let error {
            applicationRead = consume protector
            throw .record(error)
        }
        let count = protector.lastOpenedByteCount
        let result = OwnedBytes(copying: destination.span.extracting(0..<count))
        applicationRead = consume protector
        guard contentType == .applicationData else { throw .malformedInput }
        return result
    }

    /// Sends a post-handshake KeyUpdate under the current write key and then
    /// installs the next write traffic secret for subsequent records.
    public mutating func requestKeyUpdate(
        requestPeerUpdate: Bool = false
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        guard var secrets = applicationSecrets.take(),
              var oldProtector = applicationWrite.take() else {
            throw .invalidState
        }
        let message: OwnedBytes
        do {
            message = try TLS13HandshakeCodec.makeKeyUpdate(
                requestUpdate: requestPeerUpdate
            )
        } catch let error {
            applicationSecrets = consume secrets
            applicationWrite = consume oldProtector
            throw .handshake(error)
        }
        let record: OwnedBytes
        do {
            record = try TLS13HandshakeWire.seal(message, with: &oldProtector)
        } catch let error {
            applicationSecrets = consume secrets
            applicationWrite = consume oldProtector
            throw error
        }
        do {
            try secrets.updateServerTrafficSecret()
            let newProtector = try secrets.withServerTrafficSecret { secret throws(TLS13RecordError) in
                try TLS13RecordProtector(cipherSuite: secrets.cipherSuite, trafficSecret: secret)
            }
            applicationSecrets = consume secrets
            applicationWrite = consume newProtector
        } catch {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
        return try TLS13HandshakeWire.makeOutput(
            records: ContiguousArray([record]),
            completed: false
        )
    }

    /// Receives a post-handshake KeyUpdate. If the peer requests an update,
    /// the returned output contains the required response record.
    public mutating func receivePostHandshakeRecord(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        do {
            let records = try TLS13HandshakeWire.splitRecords(input)
            guard records.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            guard var protector = applicationRead.take() else { throw TLS13HandshakeEngineError.invalidState }
            let record = records[0]
            var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
            var destination = plaintext.mutableSpan
            let contentType: TLS13ContentType
            do {
                contentType = try protector.open(record: record.span, into: &destination)
            } catch {
                throw mapHandshakeEngineError(error)
            }
            guard contentType == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
            let count = protector.lastOpenedByteCount
            applicationRead = consume protector
            let messages = try engineTry {
                try TLS13HandshakeCodec.splitMessages(destination.span.extracting(0..<count))
            }
            guard messages.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            let requestPeerUpdate = try parseKeyUpdateMessage(messages[0])
            guard var secrets = applicationSecrets.take() else { throw TLS13HandshakeEngineError.invalidState }
            try secrets.updateClientTrafficSecret()
            let newProtector = try secrets.withClientTrafficSecret { secret throws(TLS13RecordError) in
                try TLS13RecordProtector(cipherSuite: secrets.cipherSuite, trafficSecret: secret)
            }
            applicationSecrets = consume secrets
            applicationRead = consume newProtector
            if requestPeerUpdate {
                return try requestKeyUpdate(requestPeerUpdate: false)
            }
            return try TLS13HandshakeWire.makeOutput(records: ContiguousArray(), completed: false)
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
    }

    private mutating func receiveClientHello(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        let records = try TLS13HandshakeWire.splitRecords(input)
        guard records.count == 1 else { throw .malformedInput }
        let record = records[0]
        guard record[0] == TLS13HandshakeWire.handshakeContentType else { throw .malformedInput }
        let clientHelloBytes = record.span.extracting(5..<record.count)
        let clientHello = try engineTry { try TLS13HandshakeCodec.parseClientHello(clientHelloBytes) }
        cipherSuite = clientHello.cipherSuite
        try appendTranscript(clientHelloBytes)

        let serverPublicKey = ephemeralKey.publicKey()
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
        let serverHello = try engineTry { try TLS13HandshakeCodec.makeServerHello(
            random: random.span,
            keyShare: serverPublicKey.span,
            cipherSuite: cipherSuite
        ) }
        try appendTranscript(serverHello.span)
        let transcriptHash = try transcriptDigest(for: cipherSuite)
        let emptyPSK = ContiguousArray<UInt8>()
        do {
            let schedule = try engineTry { try TLS13KeySchedule(
                cipherSuite: cipherSuite,
                preSharedKey: emptyPSK.span
            ) }
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
            let secrets = try engineTry {
                try schedule.makeHandshakeSecrets(
                    ecdheSharedSecret: sharedBytes.span,
                    transcriptHash: transcriptHash.span
                )
            }
            let readProtector = try engineTry { try secrets.withClientTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            } }
            let writeProtector = try engineTry { try secrets.withServerTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            } }
            handshakeSecrets = consume secrets
            handshakeRead = consume readProtector
            handshakeWrite = consume writeProtector
        } catch {
            throw mapHandshakeEngineError(error)
        }

        let encrypted = try makeServerEncryptedFlight()
        var recordsOut = ContiguousArray<OwnedBytes>()
        recordsOut.append(try TLS13HandshakeWire.makePlaintextRecord(serverHello.span))
        recordsOut.append(contentsOf: encrypted)
        phase = .awaitingClientFinished
        return try TLS13HandshakeWire.makeOutput(records: recordsOut, completed: false)
    }

    private mutating func makeServerEncryptedFlight() throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes> {
        guard let secrets = handshakeSecrets.take(),
              var protector = handshakeWrite.take() else { throw .invalidState }
        var messages = ContiguousArray<OwnedBytes>()
        let encryptedExtensions = try engineTry { try TLS13HandshakeCodec.makeEncryptedExtensions() }
        try appendTranscript(encryptedExtensions.span)
        messages.append(encryptedExtensions)
        let certificateMessage = try engineTry { try TLS13HandshakeCodec.makeCertificate(certificateDER: certificate.span) }
        try appendTranscript(certificateMessage.span)
        messages.append(certificateMessage)
        let hash = try transcriptDigest(for: cipherSuite)
        let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
        let signature = try engineTry { try signingKey.sign(message: signed.span) }
        let certificateVerify = try engineTry { try TLS13HandshakeCodec.makeCertificateVerify(signature: signature.span) }
        try appendTranscript(certificateVerify.span)
        messages.append(certificateVerify)
        let finishedHash = try transcriptDigest(for: cipherSuite)
        let finished = try engineTry { try secrets.makeServerFinishedVerifyData(transcriptHash: finishedHash.span) }
        let finishedMessage = try engineTry { try TLS13HandshakeCodec.makeFinished(verifyData: finished.span) }
        try appendTranscript(finishedMessage.span)
        messages.append(finishedMessage)
        var result = ContiguousArray<OwnedBytes>()
        for message in messages {
            result.append(try TLS13HandshakeWire.seal(message, with: &protector))
        }
        handshakeSecrets = consume secrets
        handshakeWrite = consume protector
        return result
    }

    private mutating func receiveClientFinished(
        _ input: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        let records = try TLS13HandshakeWire.splitRecords(input)
        guard records.count == 1 else { throw .malformedInput }
        guard var protector = handshakeRead.take() else { throw .invalidState }
        let record = records[0]
        var plaintext = ContiguousArray<UInt8>(repeating: 0, count: TLS13RecordProtector.maximumPlaintextByteCount + 256)
        var destination = plaintext.mutableSpan
        let contentType: TLS13ContentType
        do {
            contentType = try protector.open(record: record.span, into: &destination)
        } catch {
            if let error = error as? TLS13RecordError {
                throw .record(error)
            }
            throw .malformedInput
        }
        guard contentType == .handshake else { throw .malformedInput }
        let count = protector.lastOpenedByteCount
        handshakeRead = consume protector
        let messages = try engineTry { try TLS13HandshakeCodec.splitMessages(destination.span.extracting(0..<count)) }
        guard messages.count == 1, messages.first![0] == TLS13HandshakeCodec.finishedType else {
            throw .malformedInput
        }
        let finishedMessage = messages.first!
        let finished = try engineTry {
            try TLS13HandshakeCodec.parseFinished(
                finishedMessage.span,
                hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
            )
        }
        let hash = try transcriptDigest(for: cipherSuite)
        guard handshakeSecrets != nil else { throw .invalidState }
        let expected = try engineTry { try handshakeSecrets!.makeClientFinishedVerifyData(transcriptHash: hash.span) }
        guard ConstantTime.equal(finished.span, expected.span) else {
            throw .certificateVerifyFailure
        }
        let applicationHash = try transcriptDigest(for: cipherSuite)
        try appendTranscript(finishedMessage.span)
        let consumedSecrets = handshakeSecrets.take()!
        let applicationSecrets: TLS13ApplicationSecrets
        do {
            applicationSecrets = try consumedSecrets.makeApplicationSecrets(transcriptHash: applicationHash.span)
        } catch let error {
            throw .keySchedule(error)
        }
        var readApplication: TLS13RecordProtector? = nil
        var writeApplication: TLS13RecordProtector? = nil
        do {
            readApplication = try applicationSecrets.withClientTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            }
            writeApplication = try applicationSecrets.withServerTrafficSecret { secret in
                try TLS13RecordProtector(cipherSuite: cipherSuite, trafficSecret: secret)
            }
        } catch {
            if let error = error as? TLS13RecordError {
                throw .record(error)
            }
            throw .malformedInput
        }
        guard let readApplication, let writeApplication else { throw .malformedInput }
        self.applicationSecrets = consume applicationSecrets
        applicationRead = consume readApplication
        applicationWrite = consume writeApplication
        phase = .established
        return try TLS13HandshakeWire.makeOutput(records: ContiguousArray(), completed: true)
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

    private borrowing func transcriptDigest(
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        do {
            return try transcript.digest(for: cipherSuite)
        } catch let error {
            throw .handshake(error)
        }
    }
}

private enum TLS13HandshakeWire {
    static let handshakeContentType: UInt8 = TLS13ContentType.handshake.rawValue
    static let maximumInputByteCount = 4 * 16_384

    static func makePlaintextRecord(_ message: Span<UInt8>) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        guard message.count <= 16_384 else { throw .malformedInput }
        var bytes = ContiguousArray<UInt8>()
        bytes.reserveCapacity(5 + message.count)
        bytes.append(handshakeContentType)
        bytes.append(0x03)
        bytes.append(0x03)
        bytes.append(UInt8(truncatingIfNeeded: message.count >> 8))
        bytes.append(UInt8(truncatingIfNeeded: message.count))
        append(&bytes, message)
        return OwnedBytes(consuming: bytes)
    }

    static func seal(
        _ message: OwnedBytes,
        with protector: inout TLS13RecordProtector
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        try seal(content: message.span, contentType: .handshake, with: &protector)
    }

    static func seal(
        content: Span<UInt8>,
        contentType: TLS13ContentType,
        with protector: inout TLS13RecordProtector
    ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
        guard content.count <= TLS13RecordProtector.maximumPlaintextByteCount else {
            throw .record(.invalidContentLength(actual: content.count))
        }
        let recordCount = 5 + content.count + 1 + 16
        var bytes = ContiguousArray<UInt8>(repeating: 0, count: recordCount)
        do {
            var output = bytes.mutableSpan
            try protector.seal(content: content, contentType: contentType, into: &output)
        } catch {
            if let error = error as? TLS13RecordError {
                throw .record(error)
            }
            throw .malformedInput
        }
        return OwnedBytes(consuming: bytes)
    }

    static func splitRecords(_ input: Span<UInt8>) throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes> {
        guard input.count <= maximumInputByteCount else { throw .malformedInput }
        var cursor = ByteCursor(input)
        var result = ContiguousArray<OwnedBytes>()
        do {
            while !cursor.isAtEnd {
                guard cursor.remainingCount >= 5 else { throw ByteError.outOfBounds(offset: cursor.offset, requested: 5, available: cursor.remainingCount) }
                let start = cursor.offset
                let type = try cursor.readByte()
                guard type == TLS13ContentType.handshake.rawValue || type == TLS13ContentType.applicationData.rawValue else {
                    throw ByteError.outOfBounds(offset: start, requested: 1, available: 0)
                }
                guard try cursor.readByte() == 0x03, try cursor.readByte() == 0x03 else {
                    throw ByteError.outOfBounds(offset: start + 1, requested: 1, available: 0)
                }
                let length = Int(try cursor.readUInt16BigEndian())
                guard length <= TLS13RecordProtector.maximumCiphertextByteCount,
                      length <= cursor.remainingCount else {
                    throw ByteError.outOfBounds(offset: cursor.offset, requested: length, available: cursor.remainingCount)
                }
                _ = try cursor.readSpan(count: length)
                result.append(OwnedBytes(copying: input.extracting(start..<cursor.offset)))
            }
        } catch {
            throw .malformedInput
        }
        return result
    }

    static func makeOutput(
        records: consuming ContiguousArray<OwnedBytes>,
        completed: Bool
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        var bytes = ContiguousArray<UInt8>()
        for record in records { append(&bytes, record.span) }
        var actions = ContiguousArray<TLSStreamAction>()
        if !bytes.isEmpty {
            do {
                actions.append(.emitRecordBytes(try ByteRange(offset: 0, count: bytes.count)))
            } catch let error {
                throw .output(error)
            }
        }
        if completed {
            actions.append(.handshakeComplete)
            actions.append(.handshakeConfirmed)
        }
        return try TLS13HandshakeOutput(
            bytes: OwnedBytes(consuming: bytes),
            actions: actions
        )
    }

    static func certificateVerifyInput(transcriptHash: Span<UInt8>) -> OwnedBytes {
        var bytes = ContiguousArray<UInt8>(repeating: 0x20, count: 64)
        bytes.append(contentsOf: "TLS 1.3, server CertificateVerify".utf8)
        bytes.append(0)
        append(&bytes, transcriptHash)
        return OwnedBytes(consuming: bytes)
    }

    private static func append(_ target: inout ContiguousArray<UInt8>, _ source: Span<UInt8>) {
        var index = 0
        while index < source.count {
            target.append(source[index])
            index += 1
        }
    }

    private static func append(_ target: inout ContiguousArray<UInt8>, _ source: OwnedBytes) {
        append(&target, source.span)
    }
}

private func mapHandshakeEngineError(_ error: any Error) -> TLS13HandshakeEngineError {
    if let error = error as? TLS13HandshakeEngineError { return error }
    if let error = error as? TLS13HandshakeError { return .handshake(error) }
    if let error = error as? TLS13RecordError { return .record(error) }
    if let error = error as? TLS13KeyScheduleError { return .keySchedule(error) }
    if let error = error as? CryptoInputError { return .crypto(error) }
    if let error = error as? X25519KeyGenerationError { return .x25519(error) }
    if let error = error as? X509CertificateError { return .certificate(error) }
    if let error = error as? ByteError { return .output(error) }
    return .malformedInput
}

private func parseKeyUpdateMessage(
    _ message: OwnedBytes
) throws(TLS13HandshakeEngineError) -> Bool {
    do {
        return try TLS13HandshakeCodec.parseKeyUpdate(message.span)
    } catch let error {
        throw .handshake(error)
    }
}

private func engineTry<Result: ~Copyable>(
    _ body: () throws -> Result
) throws(TLS13HandshakeEngineError) -> Result {
    do {
        return try body()
    } catch let error {
        throw mapHandshakeEngineError(error)
    }
}

private func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return }
        SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
}
