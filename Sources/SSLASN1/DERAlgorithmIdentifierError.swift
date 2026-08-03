import SSLCore

public enum DERAlgorithmIdentifierError: Error, Sendable, Equatable {
    case malformed
    case der(DERError)
    case value(DERValueError)
    case resourceLimit(ResourceLimitError)
}
