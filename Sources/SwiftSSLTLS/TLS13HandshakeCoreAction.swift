import SwiftSSLCore

public enum TLS13HandshakeCoreAction: Sendable, Hashable {
    case emitHandshakeBytes(epoch: TLS13HandshakeEpoch, bytes: ByteRange)
    case installTrafficSecrets(epoch: TLS13HandshakeEpoch)
    case handshakeComplete
    case handshakeConfirmed

    package var referencedByteRange: ByteRange? {
        switch self {
        case .emitHandshakeBytes(_, let bytes):
            bytes
        case .installTrafficSecrets, .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
