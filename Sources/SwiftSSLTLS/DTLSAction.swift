import SwiftSSLCore

public enum DTLSAction: TLSBatchAction, Hashable {
    case emitDatagram(ByteRange)
    case deliverApplicationData(bytes: ByteRange, isEarlyData: Bool)
    case sendAlert(TLSAlert)
    case handshakeComplete
    case handshakeConfirmed
    case flushFlight

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitDatagram(range), let .deliverApplicationData(range, _):
            range
        case .sendAlert, .handshakeComplete, .handshakeConfirmed, .flushFlight:
            nil
        }
    }
}
