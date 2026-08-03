import SwiftSSLASN1
import SwiftSSLCore

public enum X509SignatureVerificationError: Error, Sendable, Equatable {
    case resourceLimit(ResourceLimitError)
    case der(DERError)
    case algorithm(DERAlgorithmIdentifierError)
    case unsupportedAlgorithm
    case invalidSignature
}
