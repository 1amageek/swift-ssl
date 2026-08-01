import SwiftSSLCore

/// Record-independent client-side TLS 1.3 handshake state transitions.
public protocol TLS13ClientHandshakeCoreProtocol: ~Copyable, Sendable {
    var isEstablished: Bool { get }

    mutating func start()
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

    mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput
}
