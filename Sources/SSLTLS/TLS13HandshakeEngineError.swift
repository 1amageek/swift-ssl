import SSLCore
import SSLCrypto
import SSLX509

public enum TLS13HandshakeEngineError: Error, Sendable, Equatable {
  case invalidState
  case invalidConfiguration
  case malformedInput
  case handshake(TLS13HandshakeError)
  case record(TLS13RecordError)
  case keySchedule(TLS13KeyScheduleError)
  case keyExchange(TLS13KeyExchangeError)
  case crypto(CryptoInputError)
  case signing(TLS13SigningError)
  case x25519(X25519KeyGenerationError)
  case certificate(X509CertificateError)
  case certificateValidation(TLS13ServerCertificateValidationError)
  case clientCertificateValidation(TLS13ClientCertificateValidationError)
  case clientCertificateRequired
  case certificateKeyMismatch
  case certificateNotValid
  case certificateVerificationFailed
  case certificateVerifyFailure
  case output(ByteError)
  case unsupportedCipherSuite(UInt16)
  case sessionTicket(TLS13SessionTicketError)
  case resumption(TLS13ResumptionError)
  case preSharedKey(TLS13PSKError)
  case ech(ECHError)
  case echRequired(retryConfigurations: ECHConfigList?)
  case applicationProtocol(TLS13ApplicationProtocolError)
  case srtp(DTLSSRTPError)
  case certificateCompression(TLS13CertificateCompressionError)
  case delegatedCredential(TLS13DelegatedCredentialError)
  case capability(TLS13CapabilityError)
  case missingTransportParameters
  case unexpectedTransportParameters
  case earlyDataReplayProtectionFailed
}
