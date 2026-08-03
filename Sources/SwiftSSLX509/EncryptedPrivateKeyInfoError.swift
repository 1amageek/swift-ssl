import SwiftSSLCore
import SwiftSSLASN1

public enum EncryptedPrivateKeyInfoError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case resourceLimit(ResourceLimitError)
    case invalidRange(ByteError)
    case unsupportedEncryptionAlgorithm
    case unsupportedKeyDerivationFunction
    case unsupportedPseudorandomFunction
    case invalidIterationCount(UInt64)
    case invalidDerivedKeyLength(UInt64)
    case invalidSaltLength(expected: Int, actual: Int)
    case invalidNonceLength(expected: Int, actual: Int)
    case invalidAuthenticationTagLength(UInt64)
    case encryptedDataTooShort(minimum: Int, actual: Int)
}
