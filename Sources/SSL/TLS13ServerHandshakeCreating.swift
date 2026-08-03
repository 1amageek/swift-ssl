import SSLCore
import SSLTLS

/// Creates a stream TLS 1.3 server that delegates credential selection and signing.
public protocol TLS13ServerHandshakeCreating: Sendable {
  func makeHandshake(
    namedGroup: TLS13NamedGroup,
    externalServerCredential: TLS13ExternalServerCredential,
    applicationProtocolSelector: (any TLS13ApplicationProtocolSelecting)?,
    clientAuthentication: TLS13ClientAuthenticationConfiguration?,
    transportParameters: Span<UInt8>?,
    resumptionIdentity: Span<UInt8>?,
    resumptionPSK: Span<UInt8>?,
    resumptionIssuedAt: VerificationInstant?,
    resumptionLifetime: UInt32?,
    resumptionAgeAdd: UInt32?,
    resumptionAgeToleranceMilliseconds: UInt32,
    resumptionMaximumEarlyDataByteCount: UInt32,
    resumptionApplicationProtocol: TLS13ApplicationProtocol?,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration?,
    echConfigurations: ECHServerConfigurationSet?
  ) throws(TLS13ServerHandshakeCreationError) -> TLS13ServerHandshake
}
