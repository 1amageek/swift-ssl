import SwiftSSLCore

/// Validates caller-acquired revocation evidence for a path ordered from leaf
/// to trust anchor. Implementations perform no fetching or other I/O.
public protocol X509RevocationEvidenceValidating: Sendable {
    func evaluate(
        path: borrowing ContiguousArray<X509Certificate>,
        evidence: borrowing ContiguousArray<X509RevocationEvidence>,
        trustedOCSPResponders: borrowing ContiguousArray<X509Certificate>,
        at instant: VerificationInstant
    ) throws(X509RevocationError)
}
