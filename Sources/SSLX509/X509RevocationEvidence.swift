public enum X509RevocationEvidence: Sendable, Hashable {
    case ocsp(OCSPResponse)
    case crl(X509CertificateRevocationList)
}
