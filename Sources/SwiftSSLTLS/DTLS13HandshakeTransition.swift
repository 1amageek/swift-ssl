/// One terminal DTLS 1.3 step with all actions produced before suspension.
public enum DTLS13HandshakeTransition: ~Copyable, Sendable {
  case output(DTLSActionBatch)
  case suspended(TLS13CapabilityRequest, DTLSActionBatch)
}
