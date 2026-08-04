import SSLTLS

/// Package-internal bridge for one canonical `SSLTLS` engine transition.
///
/// This value does not implement a second QUIC/TLS state machine. It only
/// preserves the output, suspension, or failure produced by `SSLTLS` while the
/// QUIC-specific stream wrapper decides when to consume the next message.
package enum QUICTLSCoreTransition: ~Copyable {
    case success(TLS13HandshakeCoreOutput)
    case suspended(TLS13CapabilityRequest)
    case failure(TLS13HandshakeEngineError)
}
