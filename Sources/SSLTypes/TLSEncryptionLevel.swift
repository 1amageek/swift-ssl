/// Encryption levels shared by stream, datagram, and QUIC session adapters.
public enum TLSEncryptionLevel: Sendable, Hashable, CaseIterable {
    case initial
    case earlyData
    case handshake
    case application
}
