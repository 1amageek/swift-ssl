import SSLCore
import SSLCrypto
import XCTest

@testable import SSLTLS

final class ECHClientHelloTests: XCTestCase {
  func testX25519ECHRoundTripUsesInnerTranscriptAndPaddedPayload() throws {
    let scalar = repeated(0x41, count: 32)
    let configKey = try X25519PrivateKey(bytes: scalar.span)
    let config = try makeConfig(publicKey: configKey.publicKey())
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [config])
    )
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: RepeatingEntropy(byte: 0x53)
    )
    let templates = try makeHelloTemplates()
    let offer = try sealer.seal(
      innerClientHello: templates.inner.span,
      outerClientHello: templates.outer.span
    )

    let serverKey = try X25519PrivateKey(bytes: scalar.span)
    let serverConfig = try ECHServerConfiguration(
      config: config,
      privateKey: serverKey
    )
    var opener = try RFC9849ECHClientHelloOpener(configuration: serverConfig)
    let opened = try opener.open(offer.outerClientHello.span)

    XCTAssertEqual(opened.innerClientHello, offer.innerClientHello)
    XCTAssertEqual(opened.configID, 17)
    let parsedInner = try TLS13HandshakeCodec.parseClientHello(
      opened.innerClientHello.span
    )
    let parsedOuter = try TLS13HandshakeCodec.parseClientHello(
      offer.outerClientHello.span
    )
    XCTAssertEqual(parsedInner.random, OwnedBytes(copying: repeated(0x11, count: 32).span))
    XCTAssertEqual(parsedOuter.random, OwnedBytes(copying: repeated(0x22, count: 32).span))

    let parsedECH = try ECHClientHelloCodec.parseOuter(offer.outerClientHello.span)
    XCTAssertEqual(parsedECH.encapsulationRange.count, X25519PublicKey.byteCount)
    XCTAssertEqual(
      parsedECH.payloadRange.count - HPKEAEAD.tagByteCount,
      ((parsedECH.payloadRange.count - HPKEAEAD.tagByteCount + 31) / 32) * 32
    )
  }

  func testOuterAADMutationIsRejectedBeforeInnerUse() throws {
    var fixture = try makeOfferAndConfig()
    var mutated = copy(fixture.offer.outerClientHello.span)
    mutated[8] ^= 0x80

    XCTAssertThrowsError(
      try fixture.opener.open(mutated.span)
    ) { error in
      XCTAssertEqual(error as? ECHError, .payloadAuthenticationFailed)
    }
  }

  func testPayloadMutationIsRejected() throws {
    var fixture = try makeOfferAndConfig()
    let parsed = try ECHClientHelloCodec.parseOuter(fixture.offer.outerClientHello.span)
    var mutated = copy(fixture.offer.outerClientHello.span)
    mutated[4 + parsed.payloadRange.offset] ^= 0x01

    XCTAssertThrowsError(
      try fixture.opener.open(mutated.span)
    ) { error in
      XCTAssertEqual(error as? ECHError, .payloadAuthenticationFailed)
    }
  }

  func testInvalidEncapsulationPreservesHPKEFailure() throws {
    var fixture = try makeOfferAndConfig()
    let parsed = try ECHClientHelloCodec.parseOuter(fixture.offer.outerClientHello.span)
    var mutated = copy(fixture.offer.outerClientHello.span)
    var index = parsed.encapsulationRange.offset
    while index < parsed.encapsulationRange.endOffset {
      mutated[4 + index] = 0
      index += 1
    }

    XCTAssertThrowsError(
      try fixture.opener.open(mutated.span)
    ) { error in
      XCTAssertEqual(error as? ECHError, .hpke(.primitive(.invalidPeerKey)))
    }
  }

  func testConfigIdentifierMismatchDoesNotAttemptDecryption() throws {
    let fixture = try makeOfferAndConfig(configID: 17)
    let otherScalar = repeated(0x41, count: 32)
    let otherKey = try X25519PrivateKey(bytes: otherScalar.span)
    let otherConfig = try makeConfig(publicKey: otherKey.publicKey(), configID: 18)
    let serverConfig = try ECHServerConfiguration(
      config: otherConfig,
      privateKey: otherKey
    )

    var opener = try RFC9849ECHClientHelloOpener(configuration: serverConfig)
    XCTAssertThrowsError(
      try opener.open(fixture.offer.outerClientHello.span)
    ) { error in
      XCTAssertEqual(error as? ECHError, .noCompatibleConfiguration)
    }
  }

  func testSecondClientHelloReusesContextAndOmitsEncapsulation() throws {
    let scalar = repeated(0x61, count: 32)
    let configKey = try X25519PrivateKey(bytes: scalar.span)
    let config = try makeConfig(publicKey: configKey.publicKey())
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [config])
    )
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: RepeatingEntropy(byte: 0x73)
    )
    let templates = try makeHelloTemplates()
    let first = try sealer.seal(
      innerClientHello: templates.inner.span,
      outerClientHello: templates.outer.span
    )
    let second = try sealer.seal(
      innerClientHello: templates.inner.span,
      outerClientHello: templates.outer.span
    )
    let parsed = try ECHClientHelloCodec.parseOuter(second.outerClientHello.span)

    XCTAssertEqual(parsed.encapsulationRange.count, 0)
    let firstServerKey = try X25519PrivateKey(bytes: scalar.span)
    let serverConfig = try ECHServerConfiguration(
      config: config,
      privateKey: firstServerKey
    )
    var opener = try RFC9849ECHClientHelloOpener(configuration: serverConfig)
    _ = try opener.open(first.outerClientHello.span)
    let openedSecond = try opener.open(second.outerClientHello.span)
    XCTAssertEqual(openedSecond.innerClientHello, second.innerClientHello)
  }

  func testConfigurationIdentifierCollisionUsesAuthenticatedTrialDecryption() throws {
    let goodScalar = repeated(0x41, count: 32)
    let goodKey = try X25519PrivateKey(bytes: goodScalar.span)
    let goodConfig = try makeConfig(publicKey: goodKey.publicKey(), configID: 17)
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [goodConfig])
    )
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: RepeatingEntropy(byte: 0x53)
    )
    let templates = try makeHelloTemplates()
    let offer = try sealer.seal(
      innerClientHello: templates.inner.span,
      outerClientHello: templates.outer.span
    )

    let wrongScalar = repeated(0x42, count: 32)
    let wrongKey = try X25519PrivateKey(bytes: wrongScalar.span)
    let wrongConfig = try makeConfig(publicKey: wrongKey.publicKey(), configID: 17)
    let configurations = try ECHServerConfigurationSet(configurations: [
      try ECHServerConfiguration(
        config: wrongConfig,
        privateKey: X25519PrivateKey(bytes: wrongScalar.span)
      ),
      try ECHServerConfiguration(
        config: goodConfig,
        privateKey: X25519PrivateKey(bytes: goodScalar.span)
      ),
    ])
    var opener = RFC9849ECHClientHelloOpener(configurations: configurations)
    let opened = try opener.open(offer.outerClientHello.span)

    XCTAssertEqual(opened.innerClientHello, offer.innerClientHello)
  }

  private func makeOfferAndConfig(
    configID: UInt8 = 17
  ) throws -> OfferFixture {
    let scalar = repeated(0x41, count: 32)
    let configKey = try X25519PrivateKey(bytes: scalar.span)
    let config = try makeConfig(
      publicKey: configKey.publicKey(),
      configID: configID
    )
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [config])
    )
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: RepeatingEntropy(byte: 0x53)
    )
    let templates = try makeHelloTemplates()
    let offer = try sealer.seal(
      innerClientHello: templates.inner.span,
      outerClientHello: templates.outer.span
    )
    let serverKey = try X25519PrivateKey(bytes: scalar.span)
    let serverConfig = try ECHServerConfiguration(
      config: config,
      privateKey: serverKey
    )
    return OfferFixture(
      offer: offer,
      opener: try RFC9849ECHClientHelloOpener(configuration: serverConfig)
    )
  }

  private func makeConfig(
    publicKey: X25519PublicKey,
    configID: UInt8 = 17
  ) throws -> ECHConfig {
    try ECHConfig(
      configID: configID,
      publicKey: publicKey.span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 64,
      publicName: ascii("public.example").span
    )
  }

  private func makeHelloTemplates() throws -> (inner: OwnedBytes, outer: OwnedBytes) {
    let keyShare = repeated(0x31, count: 32)
    return (
      try TLS13HandshakeCodec.makeClientHello(
        random: repeated(0x11, count: 32).span,
        keyShare: keyShare.span
      ),
      try TLS13HandshakeCodec.makeClientHello(
        random: repeated(0x22, count: 32).span,
        keyShare: keyShare.span
      )
    )
  }

  private struct RepeatingEntropy: EntropySource {
    let byte: UInt8

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
    }
  }

  private struct OfferFixture: ~Copyable {
    let offer: ECHClientHelloOffer
    var opener: RFC9849ECHClientHelloOpener
  }

  private func ascii(_ value: String) -> ContiguousArray<UInt8> {
    ContiguousArray(value.utf8)
  }

  private func repeated(_ byte: UInt8, count: Int) -> ContiguousArray<UInt8> {
    ContiguousArray(repeating: byte, count: count)
  }

  private func copy(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
      result.append(bytes[index])
      index += 1
    }
    return result
  }
}
