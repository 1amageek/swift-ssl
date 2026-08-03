public enum TLS13HandshakeEpoch: Sendable, Hashable {
    case initial
    case earlyData
    case handshake
    case application
}
