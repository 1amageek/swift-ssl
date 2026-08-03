/// One terminal stream TLS step with all output produced before suspension.
public enum TLS13StreamHandshakeTransition: ~Copyable, Sendable {
  case output(TLS13HandshakeOutput)
  case suspended(TLS13CapabilityRequest, TLS13HandshakeOutput)
}
