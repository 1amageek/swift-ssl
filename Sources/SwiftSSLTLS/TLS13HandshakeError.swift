import SwiftSSLCore

public enum TLS13HandshakeError: Error, Sendable, Equatable {
    case transcriptTooLong(limit: Int, attempted: Int)
    case malformedMessage
    case unexpectedMessage(type: UInt8)
    case unsupportedCipherSuite(UInt16)
    case unsupportedExtension(UInt16)
    case invalidKeyShare
    case invalidPreSharedKey
    case invalidFinished
    case certificateFailure
    case signatureFailure
    case invalidState
    case recordFailure(TLS13RecordError)
    case keyScheduleFailure(TLS13KeyScheduleError)
    case cryptographicFailure
}
