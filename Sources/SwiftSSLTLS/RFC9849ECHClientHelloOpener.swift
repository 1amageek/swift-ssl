import SwiftSSLCore
import SwiftSSLCrypto

/// Pure Swift RFC 9849 ClientHello decryption over X25519 HPKE.
public struct RFC9849ECHClientHelloOpener: ECHClientHelloOpening, ~Copyable, Sendable {
  private enum Phase: Sendable {
    case awaitingInitial
    case awaitingSecond
    case failed
  }

  private let configurations: ECHServerConfigurationSet
  private var context: HPKERecipientContext?
  private var selectedConfigID: UInt8?
  private var selectedCipherSuite: ECHCipherSuite?
  private var phase: Phase

  public init(configurations: ECHServerConfigurationSet) {
    self.configurations = configurations
    context = nil
    selectedConfigID = nil
    selectedCipherSuite = nil
    phase = .awaitingInitial
  }

  public init(configuration: ECHServerConfiguration) throws(ECHError) {
    self.init(
      configurations: try ECHServerConfigurationSet(
        configurations: [configuration]
      )
    )
  }

  public mutating func open(
    _ outerClientHello: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> ECHOpenedClientHello {
    do {
      let parsed = try ECHClientHelloCodec.parseOuter(
        outerClientHello,
        encoding: encoding
      )
      let outerBody = outerClientHello.extracting(4..<outerClientHello.count)
      let encapsulation = outerBody.extracting(
        parsed.encapsulationRange.offset..<parsed.encapsulationRange.endOffset
      )
      let ciphertext = outerBody.extracting(
        parsed.payloadRange.offset..<parsed.payloadRange.endOffset
      )
      switch phase {
      case .awaitingInitial:
        guard !encapsulation.isEmpty else {
          throw ECHError.invalidClientHello
        }
        return try openInitial(
          parsed,
          encapsulation: encapsulation,
          ciphertext: ciphertext,
          encoding: encoding
        )
      case .awaitingSecond:
        guard encapsulation.isEmpty,
          parsed.configID == selectedConfigID,
          parsed.cipherSuite == selectedCipherSuite,
          var retained = context.take()
        else {
          throw ECHError.invalidClientHello
        }
        let inner = try decrypt(
          parsed,
          ciphertext: ciphertext,
          encoding: encoding,
          using: &retained
        )
        context = consume retained
        phase = .awaitingSecond
        return ECHOpenedClientHello(
          innerClientHello: inner,
          configID: parsed.configID,
          cipherSuite: parsed.cipherSuite
        )
      case .failed:
        throw ECHError.invalidClientHello
      }
    } catch let error as ECHError {
      phase = .failed
      throw error
    } catch {
      phase = .failed
      throw .invalidClientHello
    }
  }

  private mutating func openInitial(
    _ parsed: ECHParsedOuter,
    encapsulation: Span<UInt8>,
    ciphertext: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) -> ECHOpenedClientHello {
    guard let kdf = parsed.cipherSuite.kdf,
      let aead = parsed.cipherSuite.aead
    else {
      throw .noCompatibleConfiguration
    }
    var hadCandidate = false
    for configuration in configurations.configurations
    where configuration.config.configID == parsed.configID
      && configuration.config.cipherSuites.contains(parsed.cipherSuite)
    {
      hadCandidate = true
      let info = ECHClientHelloCodec.makeHPKEInfo(config: configuration.config)
      let initialized: HPKERecipientContext
      do {
        initialized = try configuration.withKeyPair {
          keyPair throws(HPKEError) in
          try HPKEX25519.setupBaseRecipient(
            encapsulation: encapsulation,
            recipientKeyPair: keyPair,
            info: info.span,
            kdf: kdf,
            aead: aead
          )
        }
      } catch let error {
        throw .hpke(error)
      }
      var recipient = consume initialized
      do {
        let inner = try decrypt(
          parsed,
          ciphertext: ciphertext,
          encoding: encoding,
          using: &recipient
        )
        context = consume recipient
        selectedConfigID = parsed.configID
        selectedCipherSuite = parsed.cipherSuite
        phase = .awaitingSecond
        return ECHOpenedClientHello(
          innerClientHello: inner,
          configID: parsed.configID,
          cipherSuite: parsed.cipherSuite
        )
      } catch ECHError.payloadAuthenticationFailed {
        continue
      }
    }
    if hadCandidate { throw .payloadAuthenticationFailed }
    throw .noCompatibleConfiguration
  }

  private func decrypt(
    _ parsed: ECHParsedOuter,
    ciphertext: Span<UInt8>,
    encoding: TLS13HandshakeEncoding,
    using recipient: inout HPKERecipientContext
  ) throws(ECHError) -> OwnedBytes {
    guard ciphertext.count >= HPKEAEAD.tagByteCount else {
      throw .invalidClientHello
    }
    var encoded = ContiguousArray<UInt8>(
      repeating: 0,
      count: ciphertext.count - HPKEAEAD.tagByteCount
    )
    do {
      var destination = encoded.mutableSpan
      try recipient.open(
        ciphertext: ciphertext,
        authenticatedData: parsed.body.span,
        into: &destination
      )
    } catch let error {
      if error == .authenticatedCipher(.authenticationFailed) {
        throw .payloadAuthenticationFailed
      }
      throw .hpke(error)
    }
    return try ECHClientHelloCodec.reconstructInner(
      encoded: encoded.span,
      outer: parsed,
      encoding: encoding
    )
  }
}
