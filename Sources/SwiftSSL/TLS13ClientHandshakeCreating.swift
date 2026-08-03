import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

/// Creates a complete stream TLS 1.3 client using injected platform capabilities.
public protocol TLS13ClientHandshakeCreating: Sendable {
  func makeHandshake(
    namedGroup: TLS13NamedGroup,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity?,
    externalClientCredential: TLS13ExternalClientCredential?,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>?,
    serverName: Span<UInt8>?,
    cipherSuite: TLSCipherSuite,
    resumptionState: consuming TLS13ResumptionState?,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration?,
    echConfiguration: consuming ECHClientConfiguration?
  ) throws(TLS13ClientHandshakeCreationError) -> TLS13ClientHandshake

  func makeHandshake(
    namedGroup: TLS13NamedGroup,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity?,
    externalClientCredential: TLS13ExternalClientCredential?,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>?,
    serverName: Span<UInt8>?,
    cipherSuite: TLSCipherSuite,
    resumptionState: consuming TLS13ResumptionState?,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration?,
    echConfiguration: consuming ECHClientConfiguration?
  ) throws(TLS13ClientHandshakeCreationError) -> TLS13ClientHandshake
}
