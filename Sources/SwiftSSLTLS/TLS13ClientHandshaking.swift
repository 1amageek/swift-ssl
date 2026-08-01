import SwiftSSLCore

/// Stream TLS 1.3 client operations over caller-owned transport I/O.
public protocol TLS13ClientHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }

    mutating func start() throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receive(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func sendApplicationData(_ content: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receiveApplicationRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> OwnedBytes
    mutating func receiveNewSessionTicket(
        _ input: Span<UInt8>,
        receivedAt: VerificationInstant
    ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState
    mutating func requestKeyUpdate(requestPeerUpdate: Bool)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receivePostHandshakeRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
}
