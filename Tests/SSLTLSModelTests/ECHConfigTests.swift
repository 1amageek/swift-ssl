import SSLCore
import SSLCrypto
import XCTest

@testable import SSLTLS

final class ECHConfigTests: XCTestCase {
  func testConfigurationRoundTripAndSelectionPreserveWireBytes() throws {
    let privateKey = try X25519PrivateKey(bytes: repeated(0x31, count: 32).span)
    let config = try ECHConfig(
      configID: 42,
      publicKey: privateKey.publicKey().span,
      cipherSuites: [
        ECHCipherSuite(kdf: .sha256, aead: .chaCha20Poly1305),
        ECHCipherSuite(kdf: .sha256, aead: .aes128GCM),
      ],
      maximumNameLength: 48,
      publicName: ascii("public.example").span
    )
    let list = try ECHConfigList(configurations: [config])
    let encoded = list.withEncodedBytes { copy($0) }
    let reparsed = try ECHConfigList(encoded: encoded.span)

    XCTAssertEqual(reparsed.configurations.count, 1)
    XCTAssertEqual(reparsed.withEncodedBytes { copy($0) }, encoded)
    XCTAssertEqual(reparsed.configurations[0].configID, 42)
    let parsedConfig = reparsed.configurations[0]
    let parsedPublicName = copy(parsedConfig.publicName.span)
    XCTAssertEqual(parsedPublicName, ascii("public.example"))

    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(from: reparsed)
    XCTAssertEqual(selected.config.configID, 42)
    XCTAssertEqual(
      selected.cipherSuite,
      ECHCipherSuite(kdf: .sha256, aead: .chaCha20Poly1305)
    )
  }

  func testUnknownVersionIsSkippedWithoutParsingContents() throws {
    let unknown = framedConfig(version: 0x1234, contents: [0xFF])
    let known = try makeRawConfig(
      privateScalar: 0x42,
      publicName: ascii("public.example"),
      extensionTypes: []
    )
    let encoded = configList([unknown, known])
    let parsed = try ECHConfigList(encoded: encoded.span)

    XCTAssertEqual(parsed.configurations.count, 1)
    XCTAssertEqual(parsed.configurations[0].configID, 7)
    XCTAssertEqual(parsed.withEncodedBytes { copy($0) }, encoded)
  }

  func testUnknownMandatoryExtensionMakesConfigurationIneligible() throws {
    let raw = try makeRawConfig(
      privateScalar: 0x52,
      publicName: ascii("public.example"),
      extensionTypes: [0x8001]
    )
    let parsed = try ECHConfigList(encoded: configList([raw]).span)

    XCTAssertFalse(parsed.configurations[0].isUsableByX25519Profile)
    XCTAssertThrowsError(
      try ECHX25519ConfigurationSelector().selectConfiguration(from: parsed)
    ) { error in
      XCTAssertEqual(error as? ECHError, .noCompatibleConfiguration)
    }
  }

  func testUnknownOptionalExtensionRemainsClientSelectable() throws {
    let raw = try makeRawConfig(
      privateScalar: 0x62,
      publicName: ascii("public.example"),
      extensionTypes: [0x0001]
    )
    let parsed = try ECHConfigList(encoded: configList([raw]).span)
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(from: parsed)

    XCTAssertEqual(selected.config.extensions.count, 1)
    XCTAssertFalse(selected.config.extensions[0].isMandatory)
  }

  func testDuplicateConfigurationExtensionIsRejected() throws {
    let raw = try makeRawConfig(
      privateScalar: 0x72,
      publicName: ascii("public.example"),
      extensionTypes: [0x0001, 0x0001]
    )

    XCTAssertThrowsError(try ECHConfigList(encoded: configList([raw]).span)) { error in
      XCTAssertEqual(error as? ECHError, .duplicateConfigExtension(0x0001))
    }
  }

  func testInvalidPublicNamesAreIgnoredBySelection() throws {
    let invalidNames = [
      ascii("bad_name.example"),
      ascii(".public.example"),
      ascii("public.example."),
      ascii("public.127"),
      ascii("public.0x7f"),
    ]
    for name in invalidNames {
      let raw = try makeRawConfig(
        privateScalar: 0x22,
        publicName: name,
        extensionTypes: []
      )
      let parsed = try ECHConfigList(encoded: configList([raw]).span)
      XCTAssertFalse(parsed.configurations[0].isPublicNameValid)
      XCTAssertThrowsError(
        try ECHX25519ConfigurationSelector().selectConfiguration(from: parsed)
      )
    }
  }

  func testServerConfigurationRejectsMismatchedPrivateKey() throws {
    let matching = try X25519PrivateKey(bytes: repeated(0x11, count: 32).span)
    let mismatched = try X25519PrivateKey(bytes: repeated(0x12, count: 32).span)
    let config = try ECHConfig(
      configID: 9,
      publicKey: matching.publicKey().span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 32,
      publicName: ascii("public.example").span
    )

    do {
      let unexpected = try ECHServerConfiguration(
        config: config,
        privateKey: mismatched
      )
      _ = consume unexpected
      XCTFail("a mismatched ECH private key was accepted")
    } catch let error {
      XCTAssertEqual(error, .publicKeyMismatch)
    }
  }

  func testMalformedConfigListLengthIsRejected() throws {
    let malformed = ContiguousArray<UInt8>([0x00, 0x04, 0xFE, 0x0D, 0x00])
    XCTAssertThrowsError(try ECHConfigList(encoded: malformed.span)) { error in
      XCTAssertEqual(error as? ECHError, .malformedConfigList)
    }
  }

  private func makeRawConfig(
    privateScalar: UInt8,
    publicName: ContiguousArray<UInt8>,
    extensionTypes: ContiguousArray<UInt16>
  ) throws -> ContiguousArray<UInt8> {
    let key = try X25519PrivateKey(bytes: repeated(privateScalar, count: 32).span)
    var contents = ContiguousArray<UInt8>()
    contents.append(7)
    appendUInt16(HPKEX25519.kemIdentifier, to: &contents)
    appendUInt16(UInt16(X25519PublicKey.byteCount), to: &contents)
    append(key.publicKey().span, to: &contents)
    appendUInt16(4, to: &contents)
    appendUInt16(0x0001, to: &contents)
    appendUInt16(0x0001, to: &contents)
    contents.append(64)
    contents.append(UInt8(publicName.count))
    contents.append(contentsOf: publicName)
    appendUInt16(UInt16(extensionTypes.count * 4), to: &contents)
    for type in extensionTypes {
      appendUInt16(type, to: &contents)
      appendUInt16(0, to: &contents)
    }
    return framedConfig(version: ECHConfig.version, contents: contents)
  }

  private func framedConfig(
    version: UInt16,
    contents: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    appendUInt16(version, to: &result)
    appendUInt16(UInt16(contents.count), to: &result)
    result.append(contentsOf: contents)
    return result
  }

  private func configList(
    _ configs: ContiguousArray<ContiguousArray<UInt8>>
  ) -> ContiguousArray<UInt8> {
    var byteCount = 0
    for config in configs { byteCount += config.count }
    var result = ContiguousArray<UInt8>()
    appendUInt16(UInt16(byteCount), to: &result)
    for config in configs { result.append(contentsOf: config) }
    return result
  }

  private func appendUInt16(
    _ value: UInt16,
    to bytes: inout ContiguousArray<UInt8>
  ) {
    bytes.append(UInt8(truncatingIfNeeded: value >> 8))
    bytes.append(UInt8(truncatingIfNeeded: value))
  }

  private func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
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
    append(bytes, to: &result)
    return result
  }
}
