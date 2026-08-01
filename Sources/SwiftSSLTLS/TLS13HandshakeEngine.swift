import SwiftSSLCore
import SwiftSSLASN1
import SwiftSSLCrypto
import SwiftSSLX509

/// A synchronous TLS 1.3 client handshake for the supported X25519 and
/// certificate-signature profiles. Transport I/O, buffering, and trust-store
/// lookup remain outside the engine; each step consumes complete TLS records
/// and returns one owned output batch.
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
    private let expectedServerSignatureScheme: TLS13SignatureScheme
    private let verificationInstant: VerificationInstant
    private let cipherSuite: TLSCipherSuite
    private var transcript: TLS13Transcript
    private var resumptionState: TLS13ResumptionState?
    private var resumptionPSK: SecretBytes?
    private var offeredResumption: Bool
    private var resumedHandshake: Bool
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
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        resumptionState: consuming TLS13ResumptionState? = nil,
        expectedServerSignatureScheme: TLS13SignatureScheme = .ed25519
    ) throws(TLS13HandshakeEngineError) {
        guard random.count == 32,
              expectedServerPublicKey.count == expectedServerSignatureScheme.publicKeyByteCount else {
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
        self.expectedServerSignatureScheme = expectedServerSignatureScheme
        self.verificationInstant = verificationInstant
        self.cipherSuite = cipherSuite
        self.resumptionState = resumptionState
        resumptionPSK = nil
        offeredResumption = false
        resumedHandshake = false
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
                    try TLS13PSKIdentity(
                        identity: ticket,
                        obfuscatedTicketAge: ticketAge
                    )
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
            return try completeStart(with: consume clientHello)
        } catch let error {
            phase = .failed
            throw mapHandshakeEngineError(error)
        }
    }

    private mutating func completeStart(
        with clientHello: consuming OwnedBytes
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        do {
            try transcript.append(clientHello.span)
        } catch let error {
            throw .handshake(error)
        }
        phase = .awaitingServerHello
        let record = try TLS13HandshakeWire.makePlaintextRecord(clientHello.span)
        return try TLS13HandshakeWire.makeOutput(
            records: ContiguousArray([record]),
            completed: false
        )
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

    /// Consumes one authenticated post-handshake NewSessionTicket and returns
    /// the single-use state needed by a future PSK ClientHello. The ticket is
    /// not persisted implicitly; the caller owns that policy boundary.
    public mutating func receiveNewSessionTicket(
        _ input: Span<UInt8>,
        receivedAt: VerificationInstant
    ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState {
        guard case .established = phase else { throw .invalidState }
        guard var protector = applicationRead.take() else { throw .invalidState }
        guard let secrets = applicationSecrets.take() else {
            applicationRead = consume protector
            throw .invalidState
        }
        do {
            let records = try TLS13HandshakeWire.splitRecords(input)
            guard records.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            let record = records[0]
            var plaintext = ContiguousArray<UInt8>(
                repeating: 0,
                count: TLS13RecordProtector.maximumPlaintextByteCount + 256
            )
            var destination = plaintext.mutableSpan
            let contentType = try protector.open(record: record.span, into: &destination)
            guard contentType == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
            let count = protector.lastOpenedByteCount
            let messages = try engineTry {
                try TLS13HandshakeCodec.splitMessages(destination.span.extracting(0..<count))
            }
            guard messages.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
            let ticket: TLS13NewSessionTicket
            var pendingMessages = messages
            let encodedTicket = pendingMessages.removeFirst()
            ticket = try TLS13SessionTicketCodec.parseNewSessionTicket(encodedTicket.span)
            let state = try secrets.withResumptionMasterSecret { master throws(TLS13ResumptionError) in
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
            applicationRead = consume protector
            return state
        } catch let error as TLS13HandshakeEngineError {
            phase = .failed
            throw error
        } catch let error as TLS13SessionTicketError {
            phase = .failed
            throw .sessionTicket(error)
        } catch let error as TLS13ResumptionError {
            phase = .failed
            throw .resumption(error)
        } catch {
            phase = .failed
            throw .malformedInput
        }
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
        guard !serverHello.selectedPreSharedKey || offeredResumption else {
            throw .handshake(.unexpectedMessage(type: TLS13HandshakeCodec.serverHelloType))
        }
        resumedHandshake = offeredResumption && serverHello.selectedPreSharedKey
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
        do {
            let schedule: TLS13KeySchedule
            if resumedHandshake {
                guard let psk = resumptionPSK.take() else { throw TLS13HandshakeEngineError.invalidState }
                do {
                    schedule = try psk.withBorrowedBytes { bytes in
                        try TLS13KeySchedule(
                            cipherSuite: serverHello.cipherSuite,
                            preSharedKey: bytes
                        )
                    }
                } catch {
                    throw mapHandshakeEngineError(error)
                }
            } else {
                resumptionPSK = nil
                let emptyPSK = ContiguousArray<UInt8>()
                schedule = try engineTry { try TLS13KeySchedule(
                    cipherSuite: serverHello.cipherSuite,
                    preSharedKey: emptyPSK.span
                ) }
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
            } catch let error as TLS13KeyScheduleError {
                throw TLS13HandshakeEngineError.keySchedule(error)
            } catch {
                throw TLS13HandshakeEngineError.malformedInput
            }
            var readProtector: TLS13RecordProtector? = nil
            var writeProtector: TLS13RecordProtector? = nil
            do {
                readProtector = try makeServerTrafficProtector(
                    secrets: secrets,
                    cipherSuite: serverHello.cipherSuite
                )
                writeProtector = try makeClientTrafficProtector(
                    secrets: secrets,
                    cipherSuite: serverHello.cipherSuite
                )
            } catch let error as TLS13RecordError {
                throw TLS13HandshakeEngineError.record(error)
            } catch {
                throw TLS13HandshakeEngineError.malformedInput
            }
            guard let readProtector, let writeProtector else {
                throw TLS13HandshakeEngineError.malformedInput
            }
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

    private func verifyCertificateVerify(
        _ value: TLS13CertificateVerify,
        signedMessage: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> Bool {
        do {
            switch value.signatureScheme {
            case .ed25519:
                return try Ed25519.verify(
                    signature: value.signature.span,
                    message: signedMessage,
                    publicKey: expectedServerPublicKey.span
                )
            case .ecdsaP256SHA256:
                let rawSignature = try decodeECDSASignature(
                    value.signature.span,
                    componentByteCount: 32
                )
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
                var destination = digest.mutableSpan
                try SHA256.hash(signedMessage, into: &destination)
                let key = try P256PublicKey(bytes: expectedServerPublicKey.span)
                return try P256ECDSA.verify(
                    signature: rawSignature.span,
                    messageHash: digest.span,
                    publicKey: key
                )
            case .ecdsaP384SHA384:
                let rawSignature = try decodeECDSASignature(
                    value.signature.span,
                    componentByteCount: 48
                )
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
                var destination = digest.mutableSpan
                try SHA384.hash(signedMessage, into: &destination)
                let key = try P384PublicKey(bytes: expectedServerPublicKey.span)
                return try P384ECDSA.verify(
                    signature: rawSignature.span,
                    messageHash: digest.span,
                    publicKey: key.span
                )
            case .ecdsaP521SHA512:
                let rawSignature = try decodeECDSASignature(
                    value.signature.span,
                    componentByteCount: 66
                )
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
                var destination = digest.mutableSpan
                try SHA512.hash(signedMessage, into: &destination)
                let key = try P521PublicKey(bytes: expectedServerPublicKey.span)
                return try P521ECDSA.verify(
                    signature: rawSignature.span,
                    messageHash: digest.span,
                    publicKey: key.span
                )
            case .rsaPSSRSAESHA256, .rsaPSSRSAESHA384, .rsaPSSRSAESHA512,
                 .rsaPSSPSSSHA256, .rsaPSSPSSSHA384, .rsaPSSPSSSHA512:
                throw TLS13HandshakeEngineError.certificateVerifyFailure
            }
        } catch let error as TLS13HandshakeEngineError {
            throw error
        } catch {
            throw .certificateVerifyFailure
        }
    }

    private func decodeECDSASignature(
        _ signature: Span<UInt8>,
        componentByteCount: Int
    ) throws(TLS13HandshakeEngineError) -> ContiguousArray<UInt8> {
        guard signature.count <= 256 else { throw .certificateVerifyFailure }
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: signature.count
            )
        } catch {
            throw .certificateVerifyFailure
        }
        var cursor = DERCursor(signature)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .certificateVerifyFailure
        }
        guard root.tag == DERTag(tagClass: .universal, isConstructed: true, number: 16) else {
            throw .certificateVerifyFailure
        }
        var body = DERCursor(root.contentBytes)
        let rElement: DERElementView
        let sElement: DERElementView
        do {
            rElement = try body.readElement(using: &budget)
            sElement = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch {
            throw .certificateVerifyFailure
        }
        let integerTag = DERTag(tagClass: .universal, isConstructed: false, number: 2)
        guard rElement.tag == integerTag, sElement.tag == integerTag else {
            throw .certificateVerifyFailure
        }

        var result = ContiguousArray<UInt8>(repeating: 0, count: componentByteCount * 2)
        try copyPositiveInteger(
            rElement.contentBytes,
            into: &result,
            offset: 0,
            componentByteCount: componentByteCount
        )
        try copyPositiveInteger(
            sElement.contentBytes,
            into: &result,
            offset: componentByteCount,
            componentByteCount: componentByteCount
        )
        return result
    }

    private func copyPositiveInteger(
        _ bytes: Span<UInt8>,
        into result: inout ContiguousArray<UInt8>,
        offset: Int,
        componentByteCount: Int
    ) throws(TLS13HandshakeEngineError) {
        guard bytes.count > 0, bytes.count <= componentByteCount + 1,
              (bytes[0] & 0x80 == 0 || bytes[0] == 0) else {
            throw .certificateVerifyFailure
        }
        var sourceOffset = 0
        if bytes.count > 1, bytes[0] == 0 {
            guard bytes[1] & 0x80 != 0 else { throw .certificateVerifyFailure }
            sourceOffset = 1
        }
        let count = bytes.count - sourceOffset
        guard count > 0, count <= componentByteCount else {
            throw .certificateVerifyFailure
        }
        var index = 0
        while index < count {
            result[offset + componentByteCount - count + index] = bytes[sourceOffset + index]
            index += 1
        }
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
                guard !resumedHandshake, sawEncryptedExtensions, !sawCertificate else {
                    throw .malformedInput
                }
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
                guard certificate.subjectPublicKeyInfo.algorithm == expectedServerSignatureScheme.keyAlgorithm else {
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
                guard !resumedHandshake, sawCertificate, !sawCertificateVerify else {
                    throw .malformedInput
                }
                let certificateVerify = try engineTry {
                    try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message.span)
                }
                guard certificateVerify.signatureScheme == expectedServerSignatureScheme else {
                    throw .certificateVerifyFailure
                }
                let hash = try transcriptDigest(for: cipherSuite)
                let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
                let verified = try verifyCertificateVerify(
                    certificateVerify,
                    signedMessage: signed.span
                )
                guard verified else { throw .certificateVerifyFailure }
                try appendTranscript(message.span)
                sawCertificateVerify = true
            case TLS13HandshakeCodec.finishedType:
                guard !sawFinished,
                      resumedHandshake ? sawEncryptedExtensions : sawCertificateVerify else {
                    throw .malformedInput
                }
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
        guard sawEncryptedExtensions,
              sawFinished,
              resumedHandshake || (sawCertificate && sawCertificateVerify) else {
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

/// A synchronous TLS 1.3 server handshake using an explicit certificate
/// signing key and X25519 key exchange. The application supplies the
/// certificate and signing key; trust policy for clients is intentionally
/// outside this engine.
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
        guard parsed.subjectPublicKeyInfo.algorithm == signingKey.signatureScheme.keyAlgorithm else {
            throw .invalidConfiguration
        }
        guard (resumptionIdentity == nil) == (resumptionPSK == nil) else {
            throw .invalidConfiguration
        }
        let hasResumptionAgeMetadata = resumptionIssuedAt != nil
            && resumptionLifetime != nil
            && resumptionAgeAdd != nil
        guard (resumptionIdentity == nil) == !hasResumptionAgeMetadata else {
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
        let signerPublicKeyBytes: ContiguousArray<UInt8>
        do {
            signerPublicKeyBytes = try signingKey.publicKeyBytes()
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
        self.resumptionIdentity = configuredIdentity
        self.resumptionPSK = configuredPSK
        self.resumptionIssuedAt = resumptionIssuedAt
        self.resumptionLifetime = resumptionLifetime
        self.resumptionAgeAdd = resumptionAgeAdd
        self.resumptionAgeToleranceMilliseconds = resumptionAgeToleranceMilliseconds
        self.cipherSuite = .aes128GCM_SHA256
        resumedHandshake = false
        handshakeSecrets = nil
        handshakeRead = nil
        handshakeWrite = nil
        applicationSecrets = nil
        applicationRead = nil
        applicationWrite = nil
        phase = .awaitingClientHello
    }

    /// Compatibility initializer for the original Ed25519-only profile.
    /// The key is immediately wrapped in the explicit signing-key enum, so
    /// the engine has one authentication path internally.
    public init(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        certificateDER: Span<UInt8>,
        signingKey: consuming Ed25519PrivateKey,
        verificationInstant: VerificationInstant,
        resumptionIdentity: Span<UInt8>? = nil,
        resumptionPSK: Span<UInt8>? = nil,
        resumptionIssuedAt: VerificationInstant? = nil,
        resumptionLifetime: UInt32? = nil,
        resumptionAgeAdd: UInt32? = nil,
        resumptionAgeToleranceMilliseconds: UInt32 = 10_000
    ) throws(TLS13HandshakeEngineError) {
        try self.init(
            random: random,
            ephemeralKey: consume ephemeralKey,
            certificateDER: certificateDER,
            signingKey: .ed25519(signingKey),
            verificationInstant: verificationInstant,
            resumptionIdentity: resumptionIdentity,
            resumptionPSK: resumptionPSK,
            resumptionIssuedAt: resumptionIssuedAt,
            resumptionLifetime: resumptionLifetime,
            resumptionAgeAdd: resumptionAgeAdd,
            resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds
        )
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

    /// Emits one authenticated post-handshake NewSessionTicket. Ticket
    /// protection and persistence remain caller-owned; the engine only binds
    /// the supplied opaque ticket to the current TLS 1.3 application epoch.
    public mutating func sendNewSessionTicket(
        lifetime: UInt32,
        ageAdd: UInt32,
        ticketNonce: Span<UInt8>,
        ticket: Span<UInt8>,
        extensions: Span<UInt8> = Span<UInt8>()
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
        guard case .established = phase else { throw .invalidState }
        guard var protector = applicationWrite.take() else { throw .invalidState }
        do {
            let message = try engineTry {
                try TLS13SessionTicketCodec.makeNewSessionTicket(
                    lifetime: lifetime,
                    ageAdd: ageAdd,
                    ticketNonce: ticketNonce,
                    ticket: ticket,
                    extensions: extensions
                )
            }
            let record = try TLS13HandshakeWire.seal(message, with: &protector)
            let output = try TLS13HandshakeWire.makeOutput(
                records: ContiguousArray([record]),
                completed: false
            )
            applicationWrite = consume protector
            return output
        } catch {
            applicationWrite = consume protector
            throw mapHandshakeEngineError(error)
        }
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
        resumedHandshake = try acceptResumption(
            clientHello: clientHello,
            encodedClientHello: clientHelloBytes
        )
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
            cipherSuite: cipherSuite,
            selectedPreSharedKey: resumedHandshake
        ) }
        try appendTranscript(serverHello.span)
        let transcriptHash = try transcriptDigest(for: cipherSuite)
        do {
            let schedule: TLS13KeySchedule
            if resumedHandshake {
                guard resumptionPSK != nil else { throw TLS13HandshakeEngineError.invalidState }
                do {
                    schedule = try resumptionPSK!.withBorrowedBytes { bytes in
                        try TLS13KeySchedule(
                            cipherSuite: cipherSuite,
                            preSharedKey: bytes
                        )
                    }
                } catch {
                    throw mapHandshakeEngineError(error)
                }
            } else {
                let emptyPSK = ContiguousArray<UInt8>()
                schedule = try engineTry { try TLS13KeySchedule(
                    cipherSuite: cipherSuite,
                    preSharedKey: emptyPSK.span
                ) }
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
            } catch let error as TLS13KeyScheduleError {
                throw TLS13HandshakeEngineError.keySchedule(error)
            } catch {
                throw TLS13HandshakeEngineError.malformedInput
            }
            var readProtector: TLS13RecordProtector? = nil
            var writeProtector: TLS13RecordProtector? = nil
            do {
                readProtector = try makeClientTrafficProtector(
                    secrets: secrets,
                    cipherSuite: cipherSuite
                )
                writeProtector = try makeServerTrafficProtector(
                    secrets: secrets,
                    cipherSuite: cipherSuite
                )
            } catch let error as TLS13RecordError {
                throw TLS13HandshakeEngineError.record(error)
            } catch {
                throw TLS13HandshakeEngineError.malformedInput
            }
            guard let readProtector, let writeProtector else {
                throw TLS13HandshakeEngineError.malformedInput
            }
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

    private mutating func acceptResumption(
        clientHello: TLS13ClientHello,
        encodedClientHello: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> Bool {
        guard let offered = clientHello.preSharedKey,
              let configuredIdentity = resumptionIdentity,
              resumptionPSK != nil else {
            return false
        }
        guard offered.identities.count == 1, offered.binders.count == 1 else {
            return false
        }
        let offeredIdentity = offered.identities[0]
        let offeredBinder = offered.binders[0].value
        guard ConstantTime.equal(offeredIdentity.identity.span, configuredIdentity.span) else {
            return false
        }
        guard let issuedAt = resumptionIssuedAt,
              let lifetime = resumptionLifetime,
              let ageAdd = resumptionAgeAdd,
              let expectedAge = expectedObfuscatedTicketAge(
                  at: verificationInstant,
                  issuedAt: issuedAt,
                  lifetime: lifetime,
                  ageAdd: ageAdd
              ),
              ticketAgeWithinTolerance(
                  offered: offeredIdentity.obfuscatedTicketAge,
                  expected: expectedAge,
                  toleranceMilliseconds: resumptionAgeToleranceMilliseconds
              ) else {
            return false
        }

        let canonicalActual: OwnedBytes
        do {
            canonicalActual = try TLS13HandshakeCodec.makeClientHello(
                random: clientHello.random.span,
                keyShare: clientHello.keyShare.span,
                cipherSuite: clientHello.cipherSuite,
                preSharedKey: offered
            )
        } catch {
            throw mapHandshakeEngineError(error)
        }
        guard ConstantTime.equal(canonicalActual.span, encodedClientHello) else {
            return false
        }

        var zeroBinders = ContiguousArray<TLS13PSKBinder>()
        for binder in offered.binders {
            let zero = ContiguousArray<UInt8>(repeating: 0, count: binder.value.count)
            do {
                zeroBinders.append(try TLS13PSKBinder(value: zero.span))
            } catch {
                throw .preSharedKey(error)
            }
        }
        let zeroExtension: TLS13PreSharedKeyExtension
        do {
            zeroExtension = try TLS13PreSharedKeyExtension(
                identities: ContiguousArray(offered.identities),
                binders: consume zeroBinders
            )
        } catch {
            throw .preSharedKey(error)
        }
        let zeroHello: OwnedBytes
        do {
            zeroHello = try TLS13HandshakeCodec.makeClientHello(
                random: clientHello.random.span,
                keyShare: clientHello.keyShare.span,
                cipherSuite: clientHello.cipherSuite,
                preSharedKey: zeroExtension
            )
        } catch {
            throw mapHandshakeEngineError(error)
        }
        do {
            var binderTranscript = try TLS13Transcript()
            try binderTranscript.append(zeroHello.span)
            let transcriptHash = try binderTranscript.digest(for: clientHello.cipherSuite)
            return try TLS13PSKBinder.verify(
                preSharedKey: resumptionPSK!,
                cipherSuite: clientHello.cipherSuite,
                transcriptHash: transcriptHash.span,
                binder: offeredBinder.span
            )
        } catch let error as TLS13PSKError {
            throw .preSharedKey(error)
        } catch {
            throw .preSharedKey(.derivationFailed)
        }
    }

    private mutating func makeServerEncryptedFlight() throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes> {
        guard let secrets = handshakeSecrets.take(),
              var protector = handshakeWrite.take() else { throw .invalidState }
        var messages = ContiguousArray<OwnedBytes>()
        let encryptedExtensions = try engineTry { try TLS13HandshakeCodec.makeEncryptedExtensions() }
        try appendTranscript(encryptedExtensions.span)
        messages.append(encryptedExtensions)
        if !resumedHandshake {
            let certificateMessage = try engineTry { try TLS13HandshakeCodec.makeCertificate(certificateDER: certificate.span) }
            try appendTranscript(certificateMessage.span)
            messages.append(certificateMessage)
            let hash = try transcriptDigest(for: cipherSuite)
            let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
            let signature = try engineTry { try signingKey.sign(message: signed.span) }
            let wireSignature: ContiguousArray<UInt8>
            switch signingKey.signatureScheme {
            case .ed25519:
                wireSignature = signature
            case .ecdsaP256SHA256:
                wireSignature = try encodeECDSASignature(
                    signature.span,
                    componentByteCount: 32
                )
            case .ecdsaP384SHA384:
                wireSignature = try encodeECDSASignature(
                    signature.span,
                    componentByteCount: 48
                )
            case .ecdsaP521SHA512:
                wireSignature = try encodeECDSASignature(
                    signature.span,
                    componentByteCount: 66
                )
            default:
                throw .invalidConfiguration
            }
            let certificateVerify: OwnedBytes
            certificateVerify = try makeCertificateVerifyMessage(
                signatureScheme: signingKey.signatureScheme,
                signature: consume wireSignature
            )
            try appendTranscript(certificateVerify.span)
            messages.append(certificateVerify)
        }
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

    private func encodeECDSASignature(
        _ rawSignature: Span<UInt8>,
        componentByteCount: Int
    ) throws(TLS13HandshakeEngineError) -> ContiguousArray<UInt8> {
        guard rawSignature.count == componentByteCount * 2 else {
            throw .certificateVerifyFailure
        }
        let r = derInteger(rawSignature.extracting(0..<componentByteCount))
        let s = derInteger(rawSignature.extracting(componentByteCount..<rawSignature.count))
        let bodyCount = 2 + r.count + 2 + s.count
        guard bodyCount <= 255 else { throw .certificateVerifyFailure }
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bodyCount + 3)
        result.append(0x30)
        if bodyCount < 128 {
            result.append(UInt8(bodyCount))
        } else {
            result.append(0x81)
            result.append(UInt8(bodyCount))
        }
        result.append(0x02)
        result.append(UInt8(r.count))
        result.append(contentsOf: r)
        result.append(0x02)
        result.append(UInt8(s.count))
        result.append(contentsOf: s)
        return result
    }

    private func derInteger(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
        var first = 0
        while first + 1 < bytes.count, bytes[first] == 0 {
            first += 1
        }
        var result = ContiguousArray<UInt8>()
        if bytes[first] & 0x80 != 0 {
            result.append(0)
        }
        var index = first
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
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
    if let error = error as? TLS13SessionTicketError { return .sessionTicket(error) }
    if let error = error as? TLS13ResumptionError { return .resumption(error) }
    if let error = error as? TLS13PSKError { return .preSharedKey(error) }
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

private func makeClientTrafficProtector(
    secrets: borrowing TLS13HandshakeSecrets,
    cipherSuite: TLSCipherSuite
) throws(TLS13RecordError) -> TLS13RecordProtector {
    try secrets.withClientTrafficSecret { secret throws(TLS13RecordError) in
        try TLS13RecordProtector(
            cipherSuite: cipherSuite,
            trafficSecret: secret
        )
    }
}

private func makeServerTrafficProtector(
    secrets: borrowing TLS13HandshakeSecrets,
    cipherSuite: TLSCipherSuite
) throws(TLS13RecordError) -> TLS13RecordProtector {
    try secrets.withServerTrafficSecret { secret throws(TLS13RecordError) in
        try TLS13RecordProtector(
            cipherSuite: cipherSuite,
            trafficSecret: secret
        )
    }
}

private func expectedObfuscatedTicketAge(
    at instant: VerificationInstant,
    issuedAt: VerificationInstant,
    lifetime: UInt32,
    ageAdd: UInt32
) -> UInt32? {
    guard instant >= issuedAt else { return nil }
    let seconds = instant.secondsSinceUnixEpoch.subtractingReportingOverflow(
        issuedAt.secondsSinceUnixEpoch
    )
    guard !seconds.overflow, seconds.partialValue >= 0 else { return nil }
    let milliseconds = seconds.partialValue.multipliedReportingOverflow(by: 1_000)
    guard !milliseconds.overflow else { return nil }
    let nanoseconds = Int64(instant.nanoseconds) - Int64(issuedAt.nanoseconds)
    let adjusted = nanoseconds < 0
        ? milliseconds.partialValue - 1
        : milliseconds.partialValue
    guard adjusted >= 0 else { return nil }
    let lifetimeMilliseconds = UInt64(lifetime) * 1_000
    guard UInt64(adjusted) <= lifetimeMilliseconds else { return nil }
    return UInt32(truncatingIfNeeded: UInt64(adjusted) &+ UInt64(ageAdd))
}

private func ticketAgeWithinTolerance(
    offered: UInt32,
    expected: UInt32,
    toleranceMilliseconds: UInt32
) -> Bool {
    let forward = offered &- expected
    let backward = expected &- offered
    return min(forward, backward) <= toleranceMilliseconds
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

private func makeCertificateVerifyMessage(
    signatureScheme: TLS13SignatureScheme,
    signature: consuming ContiguousArray<UInt8>
) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    let owner = OwnedBytes(consuming: signature)
    do {
        return try TLS13HandshakeCodec.makeCertificateVerify(
            signatureScheme: signatureScheme,
            signature: owner.span
        )
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
