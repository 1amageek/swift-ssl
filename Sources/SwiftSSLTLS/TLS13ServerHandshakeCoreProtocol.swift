import SwiftSSLCore

/// Record-independent server-side TLS 1.3 handshake state transitions.
public protocol TLS13ServerHandshakeCoreProtocol: ~Copyable, Sendable {
    var isEstablished: Bool { get }

    mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput
}
