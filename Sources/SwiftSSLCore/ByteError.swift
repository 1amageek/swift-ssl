public enum ByteError: Error, Sendable, Equatable {
    case negativeCount(Int)
    case offsetOverflow(offset: Int, count: Int)
    case outOfBounds(offset: Int, requested: Int, available: Int)
    case trailingBytes(count: Int)
    case capacityExceeded(limit: Int, attempted: Int)
    case integerDoesNotFit(value: UInt64, byteCount: Int)
}
