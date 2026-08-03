import SwiftSSLCore

/// RFC 5280 extension policy for TLS client certificate identities.
///
/// The shared path policy requires digital-signature key usage and the
/// clientAuth extended-key-usage value when those extensions are present.
/// DNS hostname verification is intentionally not part of client identity.
public struct RFC5280ClientPathPolicy: X509PathPolicyEvaluating, Sendable {
  private let policy: RFC5280ServerPathPolicy

  public init(
    requiredCertificatePolicyObjectIdentifiers:
      ContiguousArray<ContiguousArray<UInt64>> = []
  ) {
    policy = RFC5280ServerPathPolicy(
      clientAuthenticationRequiredCertificatePolicyObjectIdentifiers:
        requiredCertificatePolicyObjectIdentifiers
    )
  }

  public func evaluate(
    path: borrowing ContiguousArray<X509Certificate>,
    hostname: Span<UInt8>?
  ) throws(X509PathError) {
    guard hostname == nil else {
      throw .identity(.malformedSubjectAlternativeName)
    }
    try policy.evaluate(path: path, hostname: nil)
  }
}
