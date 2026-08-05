import SSLCore

public enum DTLSAction: TLSBatchAction, Hashable {
    case emitDatagram(ByteRange)
    case deliverApplicationData(bytes: ByteRange, isEarlyData: Bool)
    case sendAlert(TLSAlert)
    case handshakeComplete
    case handshakeConfirmed
    case flushFlight
    case scheduleRetransmission(afterMilliseconds: UInt64)
    case cancelRetransmission

    public var referencedByteRange: ByteRange? {
        switch self {
        case let .emitDatagram(range), let .deliverApplicationData(range, _):
            range
        case .sendAlert, .handshakeComplete, .handshakeConfirmed, .flushFlight,
             .scheduleRetransmission, .cancelRetransmission:
            nil
        }
    }
}
import TLSTypes
