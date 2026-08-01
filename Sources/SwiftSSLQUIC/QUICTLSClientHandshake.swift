import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

/// QUIC client handshake driver composed from per-level CRYPTO streams and the
/// record-independent TLS 1.3 client core.
public struct QUICTLSClientHandshake: QUICTLSClientHandshaking, ~Copyable, Sendable {
    private var core: TLS13ClientHandshakeCore
    private var initialStream: QUICTLSHandshakeStream
    private var handshakeStream: QUICTLSHandshakeStream

    public static func make(
        random: Span<UInt8>,
        ephemeralKey: consuming X25519PrivateKey,
        expectedServerPublicKey: Span<UInt8>,
        verificationInstant: VerificationInstant,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        resumptionState: consuming TLS13ResumptionState? = nil,
        maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
        maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
    ) throws(QUICTLSHandshakeError) -> Self {
        let core: TLS13ClientHandshakeCore
        do {
            core = try TLS13ClientHandshakeCore(
                random: random,
                ephemeralKey: ephemeralKey,
                expectedServerPublicKey: expectedServerPublicKey,
                verificationInstant: verificationInstant,
                cipherSuite: cipherSuite,
                resumptionState: resumptionState
            )
        } catch let error {
            throw .handshake(error)
        }
        return try make(
            core: core,
            maximumBufferedByteCount: maximumBufferedByteCount,
            maximumMessageByteCount: maximumMessageByteCount
        )
    }

    public static func make(
        random: Span<UInt8>,
        keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
        expectedServerPublicKey: Span<UInt8>,
        verificationInstant: VerificationInstant,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        resumptionState: consuming TLS13ResumptionState? = nil,
        maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
        maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
    ) throws(QUICTLSHandshakeError) -> Self {
        let core: TLS13ClientHandshakeCore
        do {
            core = try TLS13ClientHandshakeCore(
                random: random,
                keyExchange: keyExchange,
                expectedServerPublicKey: expectedServerPublicKey,
                verificationInstant: verificationInstant,
                cipherSuite: cipherSuite,
                resumptionState: resumptionState
            )
        } catch let error {
            throw .handshake(error)
        }
        return try make(
            core: core,
            maximumBufferedByteCount: maximumBufferedByteCount,
            maximumMessageByteCount: maximumMessageByteCount
        )
    }

    private static func make(
        core: consuming TLS13ClientHandshakeCore,
        maximumBufferedByteCount: Int,
        maximumMessageByteCount: Int
    ) throws(QUICTLSHandshakeError) -> Self {
        let initial = try makeStream(
            level: .initial,
            maximumBufferedByteCount: maximumBufferedByteCount,
            maximumMessageByteCount: maximumMessageByteCount
        )
        let handshake = try makeStream(
            level: .handshake,
            maximumBufferedByteCount: maximumBufferedByteCount,
            maximumMessageByteCount: maximumMessageByteCount
        )
        return Self(
            core: consume core,
            initialStream: initial,
            handshakeStream: handshake
        )
    }

    private init(
        core: consuming TLS13ClientHandshakeCore,
        initialStream: consuming QUICTLSHandshakeStream,
        handshakeStream: consuming QUICTLSHandshakeStream
    ) {
        self.core = core
        self.initialStream = initialStream
        self.handshakeStream = handshakeStream
    }

    public var isEstablished: Bool { core.isEstablished }

    public mutating func start()
        throws(QUICTLSHandshakeError) -> QUICTLSStepOutput
    {
        let output: TLS13HandshakeCoreOutput
        do {
            output = try core.start()
        } catch let error {
            throw .handshake(error)
        }
        return try QUICTLSCoreOutputAdapter.adapt(output, role: .client)
    }

    public mutating func receiveCrypto(
        level: QUICTLSHandshakeInputLevel,
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeError) {
        do {
            switch level {
            case .initial:
                try initialStream.receive(offset: offset, bytes: bytes)
            case .handshake:
                try handshakeStream.receive(offset: offset, bytes: bytes)
            }
        } catch let error {
            throw .stream(error)
        }
    }

    public mutating func processNextMessage(
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput? {
        let produced: QUICTLSCoreTransition?
        do {
            switch level {
            case .initial:
                produced = try Self.transition(
                    from: initialStream,
                    core: &core,
                    epoch: .initial
                )
            case .handshake:
                produced = try Self.transition(
                    from: handshakeStream,
                    core: &core,
                    epoch: .handshake
                )
            }
        } catch let error {
            throw .stream(error)
        }
        guard let produced else { return nil }
        switch consume produced {
        case .failure(let error):
            throw .handshake(error)
        case .success(let output):
            do {
                switch level {
                case .initial: try initialStream.discardNextMessage()
                case .handshake: try handshakeStream.discardNextMessage()
                }
            } catch let error {
                throw .stream(error)
            }
            return try QUICTLSCoreOutputAdapter.adapt(output, role: .client)
        }
    }

    private static func transition(
        from stream: borrowing QUICTLSHandshakeStream,
        core: inout TLS13ClientHandshakeCore,
        epoch: TLS13HandshakeEpoch
    ) throws(QUICTLSHandshakeStreamError) -> QUICTLSCoreTransition? {
        try stream.withNextMessage { message in
            do {
                return .success(
                    try core.receiveHandshakeMessage(message, at: epoch)
                )
            } catch let error as TLS13HandshakeEngineError {
                return .failure(error)
            } catch {
                return .failure(.malformedInput)
            }
        }
    }

    private static func makeStream(
        level: QUICHandshakeEncryptionLevel,
        maximumBufferedByteCount: Int,
        maximumMessageByteCount: Int
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeStream {
        do {
            return try QUICTLSHandshakeStream.make(
                encryptionLevel: level,
                maximumBufferedByteCount: maximumBufferedByteCount,
                maximumMessageByteCount: maximumMessageByteCount
            )
        } catch let error {
            throw .stream(error)
        }
    }
}
