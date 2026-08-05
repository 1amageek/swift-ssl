import SSLCore

/// Immutable input for an external TLS credential provider.
public struct TLS13CredentialSelectionRequest: Sendable, Hashable {
  public let token: TLS13CapabilityToken
  public let role: TLSRole
  public let serverName: OwnedBytes?
  public let signatureSchemes: ContiguousArray<TLS13SignatureScheme>
  public let delegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme>
  public let certificateTypes: ContiguousArray<TLS13CertificateType>
  public let certificateRequestContext: OwnedBytes?
  public let verificationInstant: VerificationInstant

  package init(
    token: TLS13CapabilityToken,
    role: TLSRole,
    serverName: OwnedBytes?,
    signatureSchemes: ContiguousArray<TLS13SignatureScheme>,
    delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme>,
    certificateTypes: ContiguousArray<TLS13CertificateType> = [.x509],
    certificateRequestContext: OwnedBytes?,
    verificationInstant: VerificationInstant
  ) {
    self.token = token
    self.role = role
    self.serverName = serverName
    self.signatureSchemes = signatureSchemes
    self.delegatedCredentialAlgorithms = delegatedCredentialAlgorithms
    self.certificateTypes = certificateTypes
    self.certificateRequestContext = certificateRequestContext
    self.verificationInstant = verificationInstant
  }
}
import TLSTypes
