import SwiftSSLTLS

/// One terminal QUIC TLS step: protocol output or an external capability request.
public enum QUICTLSHandshakeTransition: ~Copyable, Sendable {
  case output(QUICTLSStepOutput)
  case suspended(TLS13CapabilityRequest)
}
