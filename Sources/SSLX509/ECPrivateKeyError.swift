import SSLCore
import SSLASN1

public enum ECPrivateKeyError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case resourceLimit(ResourceLimitError)
    case invalidVersion(UInt64)
    case invalidParameters
    case invalidPrivateKeyLength(expected: Int, actual: Int)
    case invalidPublicKeyField
    case memoryFailure(SecretMemoryError)
}
