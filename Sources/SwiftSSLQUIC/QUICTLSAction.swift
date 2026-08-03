import SwiftSSLCore
import SwiftSSLTLS

public enum QUICTLSAction: TLSBatchAction, Hashable {
    case emitHandshakeBytes(level: QUICHandshakeEncryptionLevel, bytes: ByteRange)
    case sendAlert(level: QUICHandshakeEncryptionLevel, alert: TLSAlert)
    case earlyDataAccepted
    case earlyDataRejected
    case handshakeComplete
    case handshakeConfirmed

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitHandshakeBytes(_, range):
            range
        case .sendAlert, .earlyDataAccepted, .earlyDataRejected,
             .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
