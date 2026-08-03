import SwiftSSLCore

/// One external private-key operation over a TLS CertificateVerify input.
public struct TLS13SignatureRequest: Sendable, Hashable {
  public let token: TLS13CapabilityToken
  public let role: TLSRole
  public let credentialIdentifier: OwnedBytes
  public let signatureScheme: TLS13SignatureScheme
  public let message: OwnedBytes

  package init(
    token: TLS13CapabilityToken,
    role: TLSRole,
    credentialIdentifier: OwnedBytes,
    signatureScheme: TLS13SignatureScheme,
    message: OwnedBytes
  ) {
    self.token = token
    self.role = role
    self.credentialIdentifier = credentialIdentifier
    self.signatureScheme = signatureScheme
    self.message = message
  }
}
