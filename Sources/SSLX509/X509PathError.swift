import SSLCore

public enum X509PathError: Error, Sendable, Equatable {
    case emptyTrustStore
    case invalidPathLength
    case certificateNotValid
    case issuerNotFound
    case issuerNotCA
    case issuerKeyUsageViolation
    case invalidBasicConstraints
    case loopDetected
    case pathTooLong(limit: Int)
    case unsupportedCriticalExtension(ContiguousArray<UInt64>)
    case invalidKeyUsage
    case leafKeyUsageViolation
    case invalidExtendedKeyUsage
    case extendedKeyUsageViolation
    case invalidSubjectAlternativeName
    case invalidNameConstraints
    case unsupportedNameConstraintType(UInt)
    case unsupportedNameConstraintBounds
    case excludedNameConstraint
    case permittedNameConstraintViolation
    case invalidCertificatePolicies
    case certificatePolicyViolation
    case signature(X509CertificateError)
    case identity(X509IdentityError)
}
