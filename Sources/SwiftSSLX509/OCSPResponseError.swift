import SwiftSSLASN1
import SwiftSSLCore

public enum OCSPResponseError: Error, Sendable, Equatable {
    case resourceLimit(ResourceLimitError)
    case der(DERError)
    case value(DERValueError)
    case certificate(X509CertificateError)
    case signatureAlgorithm(X509SignatureVerificationError)
    case signature(X509SignatureVerificationError)
    case certificateTransparency(CertificateTransparencyError)
    case invalidStructure
    case unsuccessfulResponse(UInt64)
    case unsupportedResponseType
    case invalidVersion
    case invalidTime
    case invalidSerialNumber
    case unsupportedIdentifierHash
    case invalidIdentifierHashLength
    case duplicateCertificateStatus
    case matchingCertificateStatusNotFound
    case unknownCertificateStatus
    case unsupportedCriticalExtension(ContiguousArray<UInt64>)
    case missingNonce
    case nonceMismatch
    case unauthorizedResponder
    case responderCertificateNotValid
    case responderCertificateKeyUsageViolation
    case responderCertificateExtendedKeyUsageViolation
    case producedInFuture
    case missingNextUpdate
    case expired
}
