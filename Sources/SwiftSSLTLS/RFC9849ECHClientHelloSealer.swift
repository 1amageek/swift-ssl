import SwiftSSLCore
import SwiftSSLCrypto

/// Pure Swift RFC 9849 ClientHello encryption over X25519 HPKE.
public struct RFC9849ECHClientHelloSealer: ECHClientHelloSealing, ~Copyable, Sendable {
  private let config: ECHConfig
  private let cipherSuite: ECHCipherSuite
  private let encapsulation: OwnedBytes
  private var context: HPKESenderContext
  private var isFirstClientHello: Bool

  public init(
    selectedConfiguration: ECHSelectedConfig,
    using entropy: borrowing any EntropySource
  ) throws(ECHError) {
    guard selectedConfiguration.config.isUsableByX25519Profile,
      selectedConfiguration.config.cipherSuites.contains(selectedConfiguration.cipherSuite),
      let kdf = selectedConfiguration.cipherSuite.kdf,
      let aead = selectedConfiguration.cipherSuite.aead
    else {
      throw .noCompatibleConfiguration
    }
    let recipient: X25519PublicKey
    do {
      recipient = try X25519PublicKey(
        bytes: selectedConfiguration.config.publicKey.span
      )
    } catch {
      throw .unsupportedKEM(selectedConfiguration.config.kemIdentifier)
    }
    let info = ECHClientHelloCodec.makeHPKEInfo(config: selectedConfiguration.config)
    let setup: HPKESenderSetup
    do {
      setup = try HPKEX25519.setupBaseSender(
        recipientPublicKey: recipient,
        info: info.span,
        kdf: kdf,
        aead: aead,
        using: entropy
      )
    } catch let error {
      throw .hpke(error)
    }
    config = selectedConfiguration.config
    cipherSuite = selectedConfiguration.cipherSuite
    encapsulation = setup.encapsulation
    context = setup.takeContext()
    isFirstClientHello = true
  }

  public mutating func seal(
    innerClientHello: Span<UInt8>,
    outerClientHello: Span<UInt8>
  ) throws(ECHError) -> ECHClientHelloOffer {
    let inner = try ECHClientHelloCodec.makeInner(
      from: innerClientHello,
      maximumNameLength: config.maximumNameLength
    )
    let payloadByteCount = inner.encoded.count + HPKEAEAD.tagByteCount
    let aad: ECHOuterAAD
    if isFirstClientHello {
      aad = try ECHClientHelloCodec.makeOuterAAD(
        from: outerClientHello,
        cipherSuite: cipherSuite,
        configID: config.configID,
        encapsulation: encapsulation.span,
        payloadByteCount: payloadByteCount
      )
    } else {
      aad = try ECHClientHelloCodec.makeOuterAAD(
        from: outerClientHello,
        cipherSuite: cipherSuite,
        configID: config.configID,
        encapsulation: Span<UInt8>(),
        payloadByteCount: payloadByteCount
      )
    }
    let encodedInner = inner.encoded
    let authenticatedOuter = aad.body
    let outer = try ECHClientHelloCodec.finishOuter(aad: aad) {
      destination throws(ECHError) in
      try sealPayload(
        encodedInner.span,
        authenticatedData: authenticatedOuter.span,
        into: &destination
      )
    }
    isFirstClientHello = false
    return ECHClientHelloOffer(
      outerClientHello: outer,
      innerClientHello: inner.clientHello
    )
  }

  private mutating func sealPayload(
    _ plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    into destination: inout MutableSpan<UInt8>
  ) throws(ECHError) {
    do {
      try context.seal(
        plaintext: plaintext,
        authenticatedData: authenticatedData,
        into: &destination
      )
    } catch let error {
      throw .hpke(error)
    }
  }
}
