import SSLCore

/// Single-owner ECH client configuration and HPKE sealing state.
public struct ECHClientConfiguration: ~Copyable, Sendable {
  public let selectedConfiguration: ECHSelectedConfig
  public let outerRandom: OwnedBytes
  private var sealer: RFC9849ECHClientHelloSealer

  public init(
    selectedConfiguration: ECHSelectedConfig,
    outerRandom: Span<UInt8>,
    using entropy: borrowing any EntropySource
  ) throws(ECHError) {
    guard outerRandom.count == 32 else { throw .invalidClientHello }
    let initializedSealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selectedConfiguration,
      using: entropy
    )
    self.selectedConfiguration = selectedConfiguration
    self.outerRandom = OwnedBytes(copying: outerRandom)
    sealer = consume initializedSealer
  }

  public var publicName: OwnedBytes {
    selectedConfiguration.config.publicName
  }

  internal borrowing func makeInnerForTranscript(
    from template: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) -> OwnedBytes {
    try ECHClientHelloCodec.makeInner(
      from: template,
      maximumNameLength: selectedConfiguration.config.maximumNameLength,
      encoding: encoding
    ).clientHello
  }

  internal mutating func seal(
    innerClientHello: Span<UInt8>,
    outerClientHello: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) -> ECHClientHelloOffer {
    try sealer.seal(
      innerClientHello: innerClientHello,
      outerClientHello: outerClientHello,
      encoding: encoding
    )
  }
}
