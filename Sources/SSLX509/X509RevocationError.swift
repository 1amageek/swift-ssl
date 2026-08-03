import SSLCore

public enum X509RevocationError: Error, Sendable, Equatable {
    case invalidPathLength
    case revoked(certificateIndex: Int, at: VerificationInstant)
    case evidenceRequired(certificateIndex: Int)
    case ocsp(certificateIndex: Int, OCSPResponseError)
    case crl(certificateIndex: Int, X509CertificateRevocationListError)
}
