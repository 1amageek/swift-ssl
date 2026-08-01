import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

/// QUIC server handshake driver composed from per-level CRYPTO streams and the
/// record-independent TLS 1.3 server core.
public struct QUICTLSServerHandshake: QUICTLSServerHandshaking, ~Copyable, Sendable {
    private var core: TLS13ServerHandshakeCore
    private var initialStream: QUICTLSHandshakeStream
    private var handshakeStream: QUICTLSHandshakeStream

    public static func make(
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
        resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
        maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
        maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
    ) throws(QUICTLSHandshakeError) -> Self {
        let core: TLS13ServerHandshakeCore
        do {
            core = try TLS13ServerHandshakeCore(
                random: random,
                ephemeralKey: ephemeralKey,
                certificateDER: certificateDER,
                signingKey: signingKey,
                verificationInstant: verificationInstant,
                resumptionIdentity: resumptionIdentity,
                resumptionPSK: resumptionPSK,
                resumptionIssuedAt: resumptionIssuedAt,
                resumptionLifetime: resumptionLifetime,
                resumptionAgeAdd: resumptionAgeAdd,
                resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds
            )
        } catch let error {
            throw .handshake(error)
        }
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
        return Self(core: core, initialStream: initial, handshakeStream: handshake)
    }

    private init(
        core: consuming TLS13ServerHandshakeCore,
        initialStream: consuming QUICTLSHandshakeStream,
        handshakeStream: consuming QUICTLSHandshakeStream
    ) {
        self.core = core
        self.initialStream = initialStream
        self.handshakeStream = handshakeStream
    }

    public var isEstablished: Bool { core.isEstablished }

    public mutating func receiveCrypto(
        level: QUICTLSHandshakeInputLevel,
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeError) {
        do {
            switch level {
            case .initial: try initialStream.receive(offset: offset, bytes: bytes)
            case .handshake: try handshakeStream.receive(offset: offset, bytes: bytes)
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
            return try QUICTLSCoreOutputAdapter.adapt(output, role: .server)
        }
    }

    private static func transition(
        from stream: borrowing QUICTLSHandshakeStream,
        core: inout TLS13ServerHandshakeCore,
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
