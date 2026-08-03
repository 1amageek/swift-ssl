import SwiftSSLASN1
import SwiftSSLCore

public enum X509CertificateRevocationListError:
    Error,
    Sendable,
    Equatable
{
    case resourceLimit(ResourceLimitError)
    case der(DERError)
    case value(DERValueError)
    case signatureAlgorithm(X509SignatureVerificationError)
    case signature(X509SignatureVerificationError)
    case invalidStructure
    case invalidVersion
    case invalidTime
    case invalidSerialNumber
    case duplicateSerialNumber
    case mismatchedSignatureAlgorithm
    case issuerMismatch
    case issuerKeyUsageViolation
    case unsupportedCriticalExtension(ContiguousArray<UInt64>)
    case unsupportedDeltaCRL
    case unsupportedIndirectCRL
    case missingNextUpdate
    case producedInFuture
    case expired
}
