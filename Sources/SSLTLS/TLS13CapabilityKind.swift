/// External capabilities that may suspend a TLS 1.3 handshake.
public enum TLS13CapabilityKind: UInt8, Sendable, Hashable {
  case peerTrustEvaluation
  case credentialSelection
  case signature
}
