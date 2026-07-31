public enum PEMError: Error, Sendable, Equatable {
    case invalidLabel
    case emptyDER
    case missingBeginBoundary
    case missingEndBoundary
    case boundaryLabelMismatch
    case invalidBoundary
    case invalidLineBreak(offset: Int)
    case lineTooLong(offset: Int, limit: Int)
    case invalidBase64Character(offset: Int)
    case invalidBase64Padding(offset: Int)
    case nonCanonicalBase64(offset: Int)
    case truncatedBase64
    case emptyPayload
    case outputLimitExceeded(limit: Int, attempted: Int)
    case integerOverflow
    case trailingData(offset: Int)
}
