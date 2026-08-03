/// The terminal result of one record-independent handshake transition.
public enum TLS13HandshakeCoreTransition: ~Copyable, Sendable {
  case output(TLS13HandshakeCoreOutput)
  case suspended(TLS13CapabilityRequest)
}
