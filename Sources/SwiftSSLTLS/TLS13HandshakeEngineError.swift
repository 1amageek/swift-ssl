import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

public enum TLS13HandshakeEngineError: Error, Sendable, Equatable {
    case invalidState
    case invalidConfiguration
    case malformedInput
    case handshake(TLS13HandshakeError)
    case record(TLS13RecordError)
    case keySchedule(TLS13KeyScheduleError)
    case crypto(CryptoInputError)
    case x25519(X25519KeyGenerationError)
    case certificate(X509CertificateError)
    case certificateKeyMismatch
    case certificateNotValid
    case certificateVerificationFailed
    case certificateVerifyFailure
    case output(ByteError)
    case unsupportedCipherSuite(UInt16)
    case sessionTicket(TLS13SessionTicketError)
    case resumption(TLS13ResumptionError)
}
