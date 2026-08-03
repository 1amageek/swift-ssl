import SSLCore
import SSLCrypto
import SSLTLS

/// Default stream TLS 1.3 server composition over explicit capability owners.
public struct DefaultTLS13ServerHandshakeFactory:
  TLS13ServerHandshakeCreating,
  Sendable
{
  private let entropy: any EntropySource
  private let wallClock: any WallClock

  public init(
    entropy: consuming any EntropySource = SystemEntropySource(),
    wallClock: consuming any WallClock = SystemWallClock()
  ) {
    self.entropy = entropy
    self.wallClock = wallClock
  }

  public func makeHandshake(
    namedGroup: TLS13NamedGroup,
    externalServerCredential: TLS13ExternalServerCredential,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13ServerHandshakeCreationError) -> TLS13ServerHandshake {
    let entropy: any EntropySource = self.entropy
    var random = ContiguousArray<UInt8>(repeating: 0, count: 32)
    do {
      var destination = random.mutableSpan
      try entropy.fill(&destination)
    } catch let error {
      throw .entropy(error)
    }

    let verificationInstant: VerificationInstant
    do {
      verificationInstant = try wallClock.now()
    } catch let error {
      throw .clock(error)
    }

    switch namedGroup {
    case .x25519:
      let ephemeralKey: SSLCrypto.X25519PrivateKey
      do {
        ephemeralKey = try SSLCrypto.X25519PrivateKey.generate(
          using: entropy
        )
      } catch let error {
        throw .keyExchange(.x25519KeyGeneration(error))
      }
      do {
        return try TLS13ServerHandshake(
          random: random.span,
          ephemeralKey: ephemeralKey,
          externalServerCredential: externalServerCredential,
          verificationInstant: verificationInstant,
          applicationProtocolSelector: applicationProtocolSelector,
          clientAuthentication: clientAuthentication,
          transportParameters: transportParameters,
          resumptionIdentity: resumptionIdentity,
          resumptionPSK: resumptionPSK,
          resumptionIssuedAt: resumptionIssuedAt,
          resumptionLifetime: resumptionLifetime,
          resumptionAgeAdd: resumptionAgeAdd,
          resumptionAgeToleranceMilliseconds:
            resumptionAgeToleranceMilliseconds,
          resumptionMaximumEarlyDataByteCount:
            resumptionMaximumEarlyDataByteCount,
          resumptionApplicationProtocol: resumptionApplicationProtocol,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfigurations: echConfigurations
        )
      } catch let error {
        throw .handshake(error)
      }
    case .secp256r1:
      let keyExchange: TLS13P256ServerKeyExchange
      do {
        keyExchange = try TLS13P256ServerKeyExchange.generate(using: entropy)
      } catch let error {
        throw .keyExchange(error)
      }
      let keyExchangeEntropy: any EntropySource = copy entropy
      do {
        return try TLS13ServerHandshake(
          random: random.span,
          keyExchange: keyExchange,
          keyExchangeEntropy: keyExchangeEntropy,
          externalServerCredential: externalServerCredential,
          verificationInstant: verificationInstant,
          applicationProtocolSelector: applicationProtocolSelector,
          clientAuthentication: clientAuthentication,
          transportParameters: transportParameters,
          resumptionIdentity: resumptionIdentity,
          resumptionPSK: resumptionPSK,
          resumptionIssuedAt: resumptionIssuedAt,
          resumptionLifetime: resumptionLifetime,
          resumptionAgeAdd: resumptionAgeAdd,
          resumptionAgeToleranceMilliseconds:
            resumptionAgeToleranceMilliseconds,
          resumptionMaximumEarlyDataByteCount:
            resumptionMaximumEarlyDataByteCount,
          resumptionApplicationProtocol: resumptionApplicationProtocol,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfigurations: echConfigurations
        )
      } catch let error {
        throw .handshake(error)
      }
    case .x25519MLKEM768:
      let keyExchange: TLS13X25519MLKEM768ServerKeyExchange
      do {
        keyExchange = try TLS13X25519MLKEM768ServerKeyExchange.generate(
          using: entropy
        )
      } catch let error {
        throw .keyExchange(error)
      }
      let keyExchangeEntropy: any EntropySource = copy entropy
      do {
        return try TLS13ServerHandshake(
          random: random.span,
          keyExchange: keyExchange,
          keyExchangeEntropy: keyExchangeEntropy,
          externalServerCredential: externalServerCredential,
          verificationInstant: verificationInstant,
          applicationProtocolSelector: applicationProtocolSelector,
          clientAuthentication: clientAuthentication,
          transportParameters: transportParameters,
          resumptionIdentity: resumptionIdentity,
          resumptionPSK: resumptionPSK,
          resumptionIssuedAt: resumptionIssuedAt,
          resumptionLifetime: resumptionLifetime,
          resumptionAgeAdd: resumptionAgeAdd,
          resumptionAgeToleranceMilliseconds:
            resumptionAgeToleranceMilliseconds,
          resumptionMaximumEarlyDataByteCount:
            resumptionMaximumEarlyDataByteCount,
          resumptionApplicationProtocol: resumptionApplicationProtocol,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfigurations: echConfigurations
        )
      } catch let error {
        throw .handshake(error)
      }
    }
  }
}
