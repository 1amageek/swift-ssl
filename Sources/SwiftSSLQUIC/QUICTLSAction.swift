import SwiftSSLCore
import SwiftSSLTLS

public enum QUICTLSAction: TLSBatchAction, Hashable {
    case emitHandshakeBytes(level: QUICHandshakeEncryptionLevel, bytes: ByteRange)
    case sendAlert(level: QUICHandshakeEncryptionLevel, alert: TLSAlert)
    case handshakeComplete
    case handshakeConfirmed

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitHandshakeBytes(_, range):
            range
        case .sendAlert, .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
