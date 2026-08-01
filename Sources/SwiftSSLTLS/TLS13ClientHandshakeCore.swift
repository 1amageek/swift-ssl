import SwiftSSLCore
import SwiftSSLASN1
import SwiftSSLCrypto
import SwiftSSLX509

/// Record-independent TLS 1.3 client state machine.
///
/// The core consumes exactly one complete handshake message per receive call.
/// It owns transcript and key-schedule state, but never frames, seals, opens,
/// retransmits, or reassembles transport bytes.
public struct TLS13ClientHandshakeCore: TLS13ClientHandshakeCoreProtocol, ~Copyable, Sendable {
    private enum Phase: Sendable {
        case idle
        case awaitingServerHello
        case awaitingServerFlight
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
            guard certificate.subjectPublicKeyInfo.algorithm
                    == expectedServerSignatureScheme.keyAlgorithm else {
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
            guard certificateVerify.signatureScheme == expectedServerSignatureScheme else {
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
            switch value.signatureScheme {
            case .ed25519:
                return try Ed25519.verify(
                    signature: value.signature.span,
                    message: signedMessage,
                    publicKey: expectedServerPublicKey.span
                )
            case .ecdsaP256SHA256:
                let raw = try decodeECDSASignature(value.signature.span, componentByteCount: 32)
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
                var destination = digest.mutableSpan
                try SHA256.hash(signedMessage, into: &destination)
                return try P256ECDSA.verify(
                    signature: raw.span,
                    messageHash: digest.span,
                    publicKey: P256PublicKey(bytes: expectedServerPublicKey.span)
                )
            case .ecdsaP384SHA384:
                let raw = try decodeECDSASignature(value.signature.span, componentByteCount: 48)
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
                var destination = digest.mutableSpan
                try SHA384.hash(signedMessage, into: &destination)
                let key = try P384PublicKey(bytes: expectedServerPublicKey.span)
                return try P384ECDSA.verify(
                    signature: raw.span,
                    messageHash: digest.span,
                    publicKey: key.span
                )
            case .ecdsaP521SHA512:
                let raw = try decodeECDSASignature(value.signature.span, componentByteCount: 66)
                var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
                var destination = digest.mutableSpan
                try SHA512.hash(signedMessage, into: &destination)
                let key = try P521PublicKey(bytes: expectedServerPublicKey.span)
                return try P521ECDSA.verify(
                    signature: raw.span,
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
        let r: DERElementView
        let s: DERElementView
        do {
            r = try body.readElement(using: &budget)
            s = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch {
            throw .certificateVerifyFailure
        }
        let integerTag = DERTag(tagClass: .universal, isConstructed: false, number: 2)
        guard r.tag == integerTag, s.tag == integerTag else {
            throw .certificateVerifyFailure
        }
        var result = ContiguousArray<UInt8>(repeating: 0, count: componentByteCount * 2)
        try copyPositiveInteger(
            r.contentBytes,
            into: &result,
            offset: 0,
            componentByteCount: componentByteCount
        )
        try copyPositiveInteger(
            s.contentBytes,
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
