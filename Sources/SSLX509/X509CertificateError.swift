import SSLCore
import SSLASN1

public enum X509CertificateError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case algorithm(DERAlgorithmIdentifierError)
    case publicKeyInfo(SubjectPublicKeyInfoError)
    case extensions(X509ExtensionError)
    case resourceLimit(ResourceLimitError)
    case invalidVersion(UInt64)
    case invalidSerialNumber
    case invalidValidity
    case invalidSignatureValue
    case unsupportedSignatureAlgorithm
    case signatureVerificationFailed
    case duplicateOptionalField
    case invalidRange(ByteError)
}
