import SwiftSSLCore

/// The correlated result of an external TLS capability operation.
public enum TLS13CapabilityResponse: Sendable, Hashable {
  case peerTrustAccepted(TLS13CapabilityToken)
  case peerTrustRejected(TLS13CapabilityToken)
  case credentialSelected(TLS13CapabilityToken, TLS13CredentialDescriptor)
  case credentialUnavailable(TLS13CapabilityToken)
  case signature(TLS13CapabilityToken, OwnedBytes)
  case signatureRejected(TLS13CapabilityToken)

  public var token: TLS13CapabilityToken {
    switch self {
    case .peerTrustAccepted(let token), .peerTrustRejected(let token): token
    case .credentialSelected(let token, _), .credentialUnavailable(let token):
      token
    case .signature(let token, _), .signatureRejected(let token): token
    }
  }

  public var kind: TLS13CapabilityKind {
    switch self {
    case .peerTrustAccepted, .peerTrustRejected:
      .peerTrustEvaluation
    case .credentialSelected, .credentialUnavailable:
      .credentialSelection
    case .signature, .signatureRejected:
      .signature
    }
  }
}
