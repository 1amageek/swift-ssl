import SSLCore

/// Immutable input for an external peer-trust evaluator.
public struct TLS13PeerTrustEvaluationRequest: Sendable, Hashable {
  public let token: TLS13CapabilityToken
  public let peer: TLS13PeerRole
  public let certificateMessage: TLS13CertificateMessage
  public let serverName: OwnedBytes?
  public let verificationInstant: VerificationInstant

  package init(
    token: TLS13CapabilityToken,
    peer: TLS13PeerRole,
    certificateMessage: TLS13CertificateMessage,
    serverName: OwnedBytes?,
    verificationInstant: VerificationInstant
  ) {
    self.token = token
    self.peer = peer
    self.certificateMessage = certificateMessage
    self.serverName = serverName
    self.verificationInstant = verificationInstant
  }
}
