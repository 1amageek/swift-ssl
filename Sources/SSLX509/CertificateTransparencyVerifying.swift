import SSLCore

public protocol CertificateTransparencyVerifying: Sendable {
    func verify(
        certificate: borrowing X509Certificate,
        timestamps: borrowing SignedCertificateTimestampList,
        logs: borrowing ContiguousArray<CertificateTransparencyLog>,
        at instant: VerificationInstant
    ) throws(CertificateTransparencyError)

    func verify(
        precertificate: borrowing RFC6962Precertificate,
        logs: borrowing ContiguousArray<CertificateTransparencyLog>,
        at instant: VerificationInstant
    ) throws(CertificateTransparencyError)
}
