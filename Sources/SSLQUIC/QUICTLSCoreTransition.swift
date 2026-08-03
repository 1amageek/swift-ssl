import SSLTLS

package enum QUICTLSCoreTransition: ~Copyable {
    case success(TLS13HandshakeCoreOutput)
    case suspended(TLS13CapabilityRequest)
    case failure(TLS13HandshakeEngineError)
}
