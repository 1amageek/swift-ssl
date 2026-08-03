import SSLCore
import SSLASN1

public enum SubjectPublicKeyInfoError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case algorithm(DERAlgorithmIdentifierError)
    case resourceLimit(ResourceLimitError)
    case invalidKeyBitString
    case invalidRange(ByteError)
}
