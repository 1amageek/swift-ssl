/// Selects external credential selection and private-key signing.
public struct TLS13ExternalServerCredential: Sendable {
  public let certificateTypes: ContiguousArray<TLS13CertificateType>

  public init(
    certificateTypes: ContiguousArray<TLS13CertificateType> = [.x509]
  ) {
    self.certificateTypes = certificateTypes
  }
}

/// Selects external client credential selection and private-key signing.
public struct TLS13ExternalClientCredential: Sendable {
  public let certificateType: TLS13CertificateType

  public init(certificateType: TLS13CertificateType = .x509) {
    self.certificateType = certificateType
  }
}
