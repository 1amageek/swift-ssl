/// QUIC encryption levels that can carry the initial TLS 1.3 handshake.
/// Post-handshake messages use a separate application-epoch responsibility.
public enum QUICTLSHandshakeInputLevel: Sendable, Hashable {
    case initial
    case handshake
}
