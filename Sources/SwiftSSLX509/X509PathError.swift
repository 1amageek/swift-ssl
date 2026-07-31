import SwiftSSLCore

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
    case signature(X509CertificateError)
    case identity(X509IdentityError)
}
