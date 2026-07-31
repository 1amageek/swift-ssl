import SwiftSSLCore

public enum DERValueError: Error, Sendable, Equatable {
    case unexpectedTag(expected: DERTag, actual: DERTag)
    case emptyInteger
    case nonCanonicalInteger
    case negativeInteger
    case invalidBoolean
    case invalidBitString
    case invalidObjectIdentifier
    case objectIdentifierOverflow
    case integerOverflow
    case invalidString
}
