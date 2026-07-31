import SwiftSSLCore

public enum TLSStreamAction: TLSBatchAction, Hashable {
    case emitRecordBytes(ByteRange)
    case deliverApplicationData(bytes: ByteRange, isEarlyData: Bool)
    case sendAlert(TLSAlert)
    case handshakeComplete
    case handshakeConfirmed

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitRecordBytes(range), let .deliverApplicationData(range, _):
            range
        case .sendAlert, .handshakeComplete, .handshakeConfirmed:
            nil
        }
    }
}
