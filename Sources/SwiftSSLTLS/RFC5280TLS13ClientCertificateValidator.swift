import SwiftSSLCore
import SwiftSSLX509

/// Composes path and revocation validation for TLS client certificates.
///
/// Trust records and revocation evidence are supplied by the caller. This
/// value performs no network, filesystem, or platform trust-store I/O.
public struct RFC5280TLS13ClientCertificateValidator:
  TLS13ClientCertificateValidating,
  Sendable
{
  private let pathValidator: X509PathValidator
  private let revocationEvaluator: RFC5280RevocationEvaluator
  private let additionalRevocationEvidence:
    ContiguousArray<X509RevocationEvidence>
  private let trustedOCSPResponders: ContiguousArray<X509Certificate>

  public init(
    trustAnchors: ContiguousArray<X509Certificate>,
    pathPolicy: any X509PathPolicyEvaluating = RFC5280ClientPathPolicy(),
    revocationPolicy: X509RevocationPolicy = X509RevocationPolicy(
      mode: .disabled
    ),
    additionalRevocationEvidence:
      ContiguousArray<X509RevocationEvidence> = [],
    trustedOCSPResponders: ContiguousArray<X509Certificate> = []
  ) throws(TLS13ClientCertificateValidationError) {
    do {
      pathValidator = try X509PathValidator(
        trustAnchors: trustAnchors,
        policy: pathPolicy
      )
    } catch let error {
      throw .path(error)
    }
    revocationEvaluator = RFC5280RevocationEvaluator(
      policy: revocationPolicy
    )
    self.additionalRevocationEvidence = additionalRevocationEvidence
    self.trustedOCSPResponders = trustedOCSPResponders
  }

  public func validate(
    _ message: borrowing TLS13CertificateMessage,
    at instant: VerificationInstant
  ) throws(TLS13ClientCertificateValidationError)
    -> TLS13ValidatedClientCertificate
  {
    guard !message.entries.isEmpty,
      message.entries.count <= TLS13CertificateMessage.maximumCertificateCount
    else {
      throw .invalidCertificateMessage
    }

    var certificates = ContiguousArray<X509Certificate>()
    certificates.reserveCapacity(message.entries.count)
    var index = 0
    while index < message.entries.count {
      let entry = message.entries[index]
      guard entry.stapledOCSPResponse == nil,
        entry.signedCertificateTimestampList == nil
      else {
        throw .invalidCertificateMessage
      }
      do {
        certificates.append(
          try X509Certificate(der: entry.certificate.span)
        )
      } catch let error {
        throw .certificate(index: index, error)
      }
      index += 1
    }

    let leaf = certificates[0]
    var intermediates = ContiguousArray<X509Certificate>()
    if certificates.count > 1 {
      intermediates.reserveCapacity(certificates.count - 1)
      index = 1
      while index < certificates.count {
        intermediates.append(certificates[index])
        index += 1
      }
    }
    let path: X509ValidatedPath
    do {
      path = try pathValidator.validate(
        leaf: leaf,
        intermediates: intermediates,
        at: instant
      )
    } catch let error {
      throw .path(error)
    }

    do {
      try revocationEvaluator.evaluate(
        path: path.certificates,
        evidence: additionalRevocationEvidence,
        trustedOCSPResponders: trustedOCSPResponders,
        at: instant
      )
    } catch let error {
      throw .revocation(error)
    }
    guard path.leaf.subjectPublicKeyInfo.isEd25519
      || path.leaf.subjectPublicKeyInfo.isP256
      || path.leaf.subjectPublicKeyInfo.isRSA
    else {
      throw .unsupportedLeafPublicKey
    }
    return TLS13ValidatedClientCertificate(
      certificateMessage: copy message,
      leafSubjectPublicKeyInfo: path.leaf.subjectPublicKeyInfo
    )
  }
}
