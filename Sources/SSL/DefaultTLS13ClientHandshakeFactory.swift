import SSLCore
import SSLCrypto
import SSLTLS

/// Default stream TLS 1.3 client composition over explicit capability owners.
public struct DefaultTLS13ClientHandshakeFactory:
  TLS13ClientHandshakeCreating,
  Sendable
{
  private let entropy: any EntropySource
  private let wallClock: any WallClock

#if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(WASILibc)
    public init(
      entropy: consuming any EntropySource = SystemEntropySource()
    ) {
      self.entropy = entropy
      self.wallClock = makeSystemWallClock()
    }
#endif

  public init(
    entropy: consuming any EntropySource = SystemEntropySource(),
    wallClock: consuming any WallClock
  ) {
    self.entropy = entropy
    self.wallClock = wallClock
  }

  public func makeHandshake(
    namedGroup: TLS13NamedGroup,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13ClientHandshakeCreationError) -> TLS13ClientHandshake {
    let (random, verificationInstant) = try makeRandomAndInstant()

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
        return try TLS13ClientHandshake(
          random: random.span,
          ephemeralKey: ephemeralKey,
          certificateValidator: certificateValidator,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    case .secp256r1:
      let keyExchange: TLS13P256ClientKeyExchange
      do {
        keyExchange = try TLS13P256ClientKeyExchange.generate(using: entropy)
      } catch let error {
        throw .keyExchange(error)
      }
      do {
        return try TLS13ClientHandshake(
          random: random.span,
          keyExchange: keyExchange,
          certificateValidator: certificateValidator,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    case .x25519MLKEM768:
      let keyExchange: TLS13X25519MLKEM768ClientKeyExchange
      do {
        keyExchange = try TLS13X25519MLKEM768ClientKeyExchange.generate(
          mlkemEntropy: entropy,
          x25519Entropy: entropy
        )
      } catch let error {
        throw .keyExchange(error)
      }
      do {
        return try TLS13ClientHandshake(
          random: random.span,
          keyExchange: keyExchange,
          certificateValidator: certificateValidator,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    }
  }

  public func makeHandshake(
    namedGroup: TLS13NamedGroup,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13ClientHandshakeCreationError) -> TLS13ClientHandshake {
    let (random, verificationInstant) = try makeRandomAndInstant()

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
        return try TLS13ClientHandshake(
          random: random.span,
          ephemeralKey: ephemeralKey,
          externalServerTrust: externalServerTrust,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    case .secp256r1:
      let keyExchange: TLS13P256ClientKeyExchange
      do {
        keyExchange = try TLS13P256ClientKeyExchange.generate(using: entropy)
      } catch let error {
        throw .keyExchange(error)
      }
      do {
        return try TLS13ClientHandshake(
          random: random.span,
          keyExchange: keyExchange,
          externalServerTrust: externalServerTrust,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    case .x25519MLKEM768:
      let keyExchange: TLS13X25519MLKEM768ClientKeyExchange
      do {
        keyExchange = try TLS13X25519MLKEM768ClientKeyExchange.generate(
          mlkemEntropy: entropy,
          x25519Entropy: entropy
        )
      } catch let error {
        throw .keyExchange(error)
      }
      do {
        return try TLS13ClientHandshake(
          random: random.span,
          keyExchange: keyExchange,
          externalServerTrust: externalServerTrust,
          clientIdentity: consume clientIdentity,
          externalClientCredential: externalClientCredential,
          applicationProtocols: applicationProtocols,
          transportParameters: transportParameters,
          serverName: serverName,
          verificationInstant: verificationInstant,
          cipherSuite: cipherSuite,
          resumptionState: consume resumptionState,
          earlyDataConfiguration: earlyDataConfiguration,
          echConfiguration: consume echConfiguration
        )
      } catch let error {
        throw .handshake(error)
      }
    }
  }

  private func makeRandomAndInstant()
    throws(TLS13ClientHandshakeCreationError) -> (
      ContiguousArray<UInt8>,
      VerificationInstant
    )
  {
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
    return (random, verificationInstant)
  }
}
