public enum QUICCryptoStreamError: Error, Sendable, Equatable {
    case invalidBufferLimit(Int)
    case offsetOutOfRange(UInt64)
    case bufferExceeded(limit: Int, endOffset: UInt64)
    case conflictingOverlap(offset: UInt64)
    case discardOutOfRange(available: Int, requested: Int)
}
