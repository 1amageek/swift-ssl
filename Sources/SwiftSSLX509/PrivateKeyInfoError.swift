import SwiftSSLCore
import SwiftSSLASN1

public enum PrivateKeyInfoError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case algorithm(DERAlgorithmIdentifierError)
    case resourceLimit(ResourceLimitError)
    case invalidVersion(UInt64)
    case invalidPublicKeyField
    case invalidRange(ByteError)
}
