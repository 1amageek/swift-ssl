import SwiftSSLTLS

package enum QUICTLSCoreTransition: ~Copyable {
    case success(TLS13HandshakeCoreOutput)
    case failure(TLS13HandshakeEngineError)
}
