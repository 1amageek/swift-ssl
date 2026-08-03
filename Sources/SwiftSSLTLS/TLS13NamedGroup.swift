/// Named groups supported by the modern TLS 1.3 key-exchange profile.
public enum TLS13NamedGroup: UInt16, Sendable, Hashable, CaseIterable {
    case secp256r1 = 0x0017
    case x25519 = 0x001D
    case x25519MLKEM768 = 0x11EC

    public var clientShareByteCount: Int {
        switch self {
        case .secp256r1: 65
        case .x25519: 32
        case .x25519MLKEM768: 1_216
        }
    }

    public var serverShareByteCount: Int {
        switch self {
        case .secp256r1: 65
        case .x25519: 32
        case .x25519MLKEM768: 1_120
        }
    }

    public var sharedSecretByteCount: Int {
        switch self {
        case .secp256r1: 32
        case .x25519: 32
        case .x25519MLKEM768: 64
        }
    }
}
