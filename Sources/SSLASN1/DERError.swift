import SSLCore

public enum DERError: Error, Sendable, Equatable {
    case truncated(offset: Int, requested: Int, available: Int)
    case invalidTag(offset: Int)
    case nonMinimalTag(offset: Int)
    case tagNumberOverflow(offset: Int)
    case indefiniteLength(offset: Int)
    case nonMinimalLength(offset: Int)
    case lengthByteCountExceeded(offset: Int, limit: Int, actual: Int)
    case lengthOverflow(offset: Int)
    case trailingData(count: Int)
    case resourceLimit(ResourceLimitError)
}
