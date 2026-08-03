/// A terminal request that suspends a TLS 1.3 handshake until resumed.
public enum TLS13CapabilityRequest: Sendable, Hashable {
  case peerTrustEvaluation(TLS13PeerTrustEvaluationRequest)
  case credentialSelection(TLS13CredentialSelectionRequest)
  case signature(TLS13SignatureRequest)

  public var token: TLS13CapabilityToken {
    switch self {
    case .peerTrustEvaluation(let request): request.token
    case .credentialSelection(let request): request.token
    case .signature(let request): request.token
    }
  }
}
