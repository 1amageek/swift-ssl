/// Selects external server-certificate trust evaluation for a client core.
public struct TLS13ExternalServerTrust: Sendable {
  public let certificateType: TLS13CertificateType

  public init(certificateType: TLS13CertificateType = .x509) {
    self.certificateType = certificateType
  }
}

/// Selects external client-certificate trust evaluation for a server core.
public struct TLS13ExternalClientTrust: Sendable {
  public let requirement: TLS13ClientCertificateRequirement
  public let certificateType: TLS13CertificateType

  public init(
    requirement: TLS13ClientCertificateRequirement,
    certificateType: TLS13CertificateType = .x509
  ) {
    self.requirement = requirement
    self.certificateType = certificateType
  }
}
