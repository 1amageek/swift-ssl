import SSLCore

/// Applies certificate-purpose and extension policy to a cryptographically
/// valid path ordered from leaf to trust anchor.
public protocol X509PathPolicyEvaluating: Sendable {
    func evaluate(
        path: borrowing ContiguousArray<X509Certificate>,
        hostname: Span<UInt8>?
    ) throws(X509PathError)
}
