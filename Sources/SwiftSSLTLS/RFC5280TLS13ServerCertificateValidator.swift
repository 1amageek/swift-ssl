import SwiftSSLCore
import SwiftSSLX509

/// Composes path, revocation, and Certificate Transparency validation for TLS.
/// Trust records and revocation/CT evidence are supplied by the caller; this
/// value never performs network or filesystem I/O.
public struct RFC5280TLS13ServerCertificateValidator:
  TLS13ServerCertificateValidating,
  Sendable
{
  private let pathValidator: X509PathValidator
  private let revocationEvaluator: RFC5280RevocationEvaluator
  private let additionalRevocationEvidence:
    ContiguousArray<X509RevocationEvidence>
  private let trustedOCSPResponders: ContiguousArray<X509Certificate>
  private let certificateTransparencyPolicy: CertificateTransparencyPolicy?
  private let certificateTransparencyLogs:
    ContiguousArray<CertificateTransparencyLog>

  public init(
    trustAnchors: ContiguousArray<X509Certificate>,
    pathPolicy: any X509PathPolicyEvaluating = RFC5280ServerPathPolicy(),
    revocationPolicy: X509RevocationPolicy = X509RevocationPolicy(
      mode: .disabled
    ),
    additionalRevocationEvidence:
      ContiguousArray<X509RevocationEvidence> = [],
    trustedOCSPResponders: ContiguousArray<X509Certificate> = [],
    certificateTransparencyPolicy: CertificateTransparencyPolicy? = nil,
    certificateTransparencyLogs:
      ContiguousArray<CertificateTransparencyLog> = []
  ) throws(TLS13ServerCertificateValidationError) {
    guard certificateTransparencyPolicy == nil
      || !certificateTransparencyLogs.isEmpty
    else {
      throw .missingCertificateTransparencyEvidence
    }
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
    self.certificateTransparencyPolicy = certificateTransparencyPolicy
    self.certificateTransparencyLogs = certificateTransparencyLogs
  }

  public func validate(
    _ message: borrowing TLS13CertificateMessage,
    serverName: Span<UInt8>?,
    at instant: VerificationInstant
  ) throws(TLS13ServerCertificateValidationError) -> SubjectPublicKeyInfo {
    guard message.requestContext.isEmpty,
      !message.entries.isEmpty,
      message.entries.count <= TLS13CertificateMessage.maximumCertificateCount
    else {
      throw .invalidCertificateMessage
    }

    var certificates = ContiguousArray<X509Certificate>()
    certificates.reserveCapacity(message.entries.count)
    var entryIndex = 0
    while entryIndex < message.entries.count {
      let entry = message.entries[entryIndex]
      do {
        certificates.append(
          try X509Certificate(der: entry.certificate.span)
        )
      } catch let error {
        throw .certificate(index: entryIndex, error)
      }
      entryIndex += 1
    }

    let leaf = certificates[0]
    var intermediates = ContiguousArray<X509Certificate>()
    if certificates.count > 1 {
      intermediates.reserveCapacity(certificates.count - 1)
      var index = 1
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
        at: instant,
        hostname: serverName
      )
    } catch let error {
      throw .path(error)
    }

    var evidence = additionalRevocationEvidence
    var stapledLeafOCSPResponse: OCSPResponse?
    entryIndex = 0
    while entryIndex < message.entries.count {
      let entry = message.entries[entryIndex]
      if let encodedOCSP = entry.stapledOCSPResponse {
        do {
          let response = try OCSPResponse(der: encodedOCSP.span)
          evidence.append(.ocsp(response))
          if entryIndex == 0 {
            stapledLeafOCSPResponse = response
          }
        } catch let error {
          throw .ocsp(index: entryIndex, error)
        }
      }
      entryIndex += 1
    }
    do {
      try revocationEvaluator.evaluate(
        path: path.certificates,
        evidence: evidence,
        trustedOCSPResponders: trustedOCSPResponders,
        at: instant
      )
    } catch let error {
      throw .revocation(error)
    }

    if let policy = certificateTransparencyPolicy {
      let verifier = RFC6962CertificateTransparencyVerifier(policy: policy)
      if let encodedList = message.entries[0]
        .signedCertificateTimestampList {
        let timestamps: SignedCertificateTimestampList
        do {
          timestamps = try SignedCertificateTimestampList(
            encoded: encodedList.span
          )
        } catch let error {
          throw .certificateTransparency(error)
        }
        do {
          try verifier.verify(
            certificate: leaf,
            timestamps: timestamps,
            logs: certificateTransparencyLogs,
            at: instant
          )
        } catch let error {
          throw .certificateTransparency(error)
        }
      } else {
        let issuerPublicKey: SubjectPublicKeyInfo
        let issuer: X509Certificate
        if path.certificates.count > 1 {
          issuer = path.certificates[1]
        } else {
          issuer = path.leaf
        }
        issuerPublicKey = issuer.subjectPublicKeyInfo
        let precertificate: RFC6962Precertificate
        do {
          precertificate = try RFC6962Precertificate(
            reconstructing: leaf,
            issuerPublicKey: issuerPublicKey
          )
          try verifier.verify(
            precertificate: precertificate,
            logs: certificateTransparencyLogs,
            at: instant
          )
        } catch let error {
          guard error == .missingEmbeddedSCTExtension,
            let stapledLeafOCSPResponse
          else {
            if error == .missingEmbeddedSCTExtension {
              throw .missingCertificateTransparencyEvidence
            }
            throw .certificateTransparency(error)
          }
          let timestamps: SignedCertificateTimestampList
          do {
            _ = try stapledLeafOCSPResponse.evaluate(
              certificate: leaf,
              issuer: issuer,
              at: instant,
              trustedResponders: trustedOCSPResponders
            )
            guard let value = try stapledLeafOCSPResponse
              .signedCertificateTimestamps(
                certificate: leaf,
                issuer: issuer
              ) else {
              throw TLS13ServerCertificateValidationError
                .missingCertificateTransparencyEvidence
            }
            timestamps = value
          } catch let validationError as TLS13ServerCertificateValidationError {
            throw validationError
          } catch let ocspError as OCSPResponseError {
            throw .ocsp(index: 0, ocspError)
          } catch {
            throw .missingCertificateTransparencyEvidence
          }
          do {
            let ocspPrecertificate = try RFC6962Precertificate(
              reconstructing: leaf,
              issuerPublicKey: issuerPublicKey,
              timestamps: timestamps
            )
            try verifier.verify(
              precertificate: ocspPrecertificate,
              logs: certificateTransparencyLogs,
              at: instant
            )
          } catch let transparencyError {
            throw .certificateTransparency(transparencyError)
          }
        }
      }
    }

    guard path.leaf.subjectPublicKeyInfo.isEd25519
      || path.leaf.subjectPublicKeyInfo.isP256
      || path.leaf.subjectPublicKeyInfo.isRSA
    else {
      throw .unsupportedLeafPublicKey
    }
    return path.leaf.subjectPublicKeyInfo
  }
}
