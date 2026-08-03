/// Server-side client-certificate policy and validation capability.
public struct TLS13ClientAuthenticationConfiguration: Sendable {
  public let requirement: TLS13ClientCertificateRequirement
  public let timing: TLS13ClientAuthenticationTiming
  package let validator: (any TLS13ClientCertificateValidating)?
  package let certificateType: TLS13CertificateType

  public init(
    requirement: TLS13ClientCertificateRequirement,
    timing: TLS13ClientAuthenticationTiming = .mainHandshake,
    validator: any TLS13ClientCertificateValidating
  ) {
    self.requirement = requirement
    self.timing = timing
    self.validator = validator
    certificateType = .x509
  }

  public init(
    externalTrust: TLS13ExternalClientTrust,
    timing: TLS13ClientAuthenticationTiming = .mainHandshake
  ) {
    requirement = externalTrust.requirement
    self.timing = timing
    validator = nil
    certificateType = externalTrust.certificateType
  }
}
