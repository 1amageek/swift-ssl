import SSLCore
import SSLTLS

public enum QUICTLSHandshakeError: Error, Sendable, Equatable {
    case handshake(TLS13HandshakeEngineError)
    case coreOutput(TLS13HandshakeCoreOutputError)
    case stepOutput(QUICTLSStepOutputError)
    case byteOutput(ByteError)
    case unsupportedEpoch(TLS13HandshakeEpoch)
    case invalidState
}
