import SwiftSSLCore

public enum TLSStreamAction: TLSBatchAction, Hashable {
    case emitRecordBytes(ByteRange)
    case deliverApplicationData(bytes: ByteRange, isEarlyData: Bool)
    case sendAlert(TLSAlert)
    case earlyDataAccepted
    case earlyDataRejected
    case handshakeComplete
    case handshakeConfirmed

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitRecordBytes(range), let .deliverApplicationData(range, _):
            range
        case .sendAlert, .earlyDataAccepted, .earlyDataRejected,
             .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
