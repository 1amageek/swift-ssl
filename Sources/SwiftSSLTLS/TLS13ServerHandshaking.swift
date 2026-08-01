import SwiftSSLCore

/// Stream TLS 1.3 server operations over caller-owned transport I/O.
public protocol TLS13ServerHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }

    mutating func receive(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func sendApplicationData(_ content: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receiveApplicationRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> OwnedBytes
    mutating func sendNewSessionTicket(
        lifetime: UInt32,
        ageAdd: UInt32,
        ticketNonce: Span<UInt8>,
        ticket: Span<UInt8>,
        extensions: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func requestKeyUpdate(requestPeerUpdate: Bool)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receivePostHandshakeRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
}
