import SwiftSSLCore

public enum TLS13HandshakeCoreAction: Sendable, Hashable {
    case emitHandshakeBytes(epoch: TLS13HandshakeEpoch, bytes: ByteRange)
    case installEarlyTrafficSecret(disposition: TLS13EarlyTrafficSecretDisposition)
    case installTrafficSecrets(epoch: TLS13HandshakeEpoch)
    case earlyDataAccepted
    case earlyDataRejected
    case handshakeComplete
    case handshakeConfirmed

    package var referencedByteRange: ByteRange? {
        switch self {
        case .emitHandshakeBytes(_, let bytes):
            bytes
        case .installEarlyTrafficSecret, .installTrafficSecrets,
             .earlyDataAccepted, .earlyDataRejected,
             .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
