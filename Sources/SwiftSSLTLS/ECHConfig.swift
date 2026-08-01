import SwiftSSLCore
import SwiftSSLCrypto

/// One RFC 9849 ECHConfig with its exact wire encoding retained for HPKE info.
public struct ECHConfig: Sendable, Hashable {
  public static let version: UInt16 = 0xFE0D

  public let configID: UInt8
  public let kemIdentifier: UInt16
  public let publicKey: OwnedBytes
  public let cipherSuites: ContiguousArray<ECHCipherSuite>
  public let maximumNameLength: UInt8
  public let publicName: OwnedBytes
  public let extensions: ContiguousArray<ECHConfigExtension>
  public let isPublicNameValid: Bool
  private let wireEncoding: OwnedBytes

  public init(
    configID: UInt8,
    publicKey: Span<UInt8>,
    cipherSuites: ContiguousArray<ECHCipherSuite>,
    maximumNameLength: UInt8,
    publicName: Span<UInt8>
  ) throws(ECHError) {
    guard publicKey.count == X25519PublicKey.byteCount else {
      throw .unsupportedKEM(HPKEX25519.kemIdentifier)
    }
    guard !cipherSuites.isEmpty else { throw .malformedConfig }
    for suite in cipherSuites {
      guard suite.isSupported else {
        throw .unsupportedCipherSuite(
          kdf: suite.kdfIdentifier,
          aead: suite.aeadIdentifier
        )
      }
    }
    guard Self.validatePublicName(publicName) else { throw .invalidPublicName }

    let encoded = try Self.encode(
      configID: configID,
      kemIdentifier: HPKEX25519.kemIdentifier,
      publicKey: publicKey,
      cipherSuites: cipherSuites,
      maximumNameLength: maximumNameLength,
      publicName: publicName,
      extensions: []
    )
    self.init(
      configID: configID,
      kemIdentifier: HPKEX25519.kemIdentifier,
      publicKey: OwnedBytes(copying: publicKey),
      cipherSuites: cipherSuites,
      maximumNameLength: maximumNameLength,
      publicName: OwnedBytes(copying: publicName),
      extensions: [],
      isPublicNameValid: true,
      wireEncoding: encoded
    )
  }

  public var isUsableByX25519Profile: Bool {
    kemIdentifier == HPKEX25519.kemIdentifier
      && publicKey.count == X25519PublicKey.byteCount
      && isPublicNameValid
      && !extensions.contains(where: { $0.isMandatory })
      && cipherSuites.contains(where: { $0.isSupported })
  }

  public borrowing func withEncodedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(wireEncoding.span)
  }

  internal init(
    configID: UInt8,
    kemIdentifier: UInt16,
    publicKey: OwnedBytes,
    cipherSuites: ContiguousArray<ECHCipherSuite>,
    maximumNameLength: UInt8,
    publicName: OwnedBytes,
    extensions: ContiguousArray<ECHConfigExtension>,
    isPublicNameValid: Bool,
    wireEncoding: OwnedBytes
  ) {
    self.configID = configID
    self.kemIdentifier = kemIdentifier
    self.publicKey = publicKey
    self.cipherSuites = copy cipherSuites
    self.maximumNameLength = maximumNameLength
    self.publicName = publicName
    self.extensions = copy extensions
    self.isPublicNameValid = isPublicNameValid
    self.wireEncoding = wireEncoding
  }

  internal static func encode(
    configID: UInt8,
    kemIdentifier: UInt16,
    publicKey: Span<UInt8>,
    cipherSuites: borrowing ContiguousArray<ECHCipherSuite>,
    maximumNameLength: UInt8,
    publicName: Span<UInt8>,
    extensions: borrowing ContiguousArray<ECHConfigExtension>
  ) throws(ECHError) -> OwnedBytes {
    guard !publicKey.isEmpty,
      publicKey.count <= UInt16.max,
      !cipherSuites.isEmpty,
      cipherSuites.count <= Int(UInt16.max) / 4,
      !publicName.isEmpty,
      publicName.count <= UInt8.max
    else {
      throw .malformedConfig
    }
    var extensionByteCount = 0
    var extensionIndex = 0
    while extensionIndex < extensions.count {
      let value = extensions[extensionIndex]
      guard value.data.count <= UInt16.max else { throw .malformedConfig }
      let (next, overflow) = extensionByteCount.addingReportingOverflow(4 + value.data.count)
      guard !overflow, next <= UInt16.max else { throw .malformedConfig }
      extensionByteCount = next
      extensionIndex += 1
    }
    let contentsByteCount =
      1 + 2 + 2 + publicKey.count + 2 + cipherSuites.count * 4
      + 1 + 1 + publicName.count + 2 + extensionByteCount
    guard contentsByteCount <= UInt16.max else { throw .malformedConfig }
    do {
      var builder = try ByteBuilder(
        maximumByteCount: Int(UInt16.max) + 4,
        minimumCapacity: contentsByteCount + 4
      )
      try builder.appendUInt16BigEndian(Self.version)
      try builder.appendUInt16BigEndian(UInt16(contentsByteCount))
      try builder.append(configID)
      try builder.appendUInt16BigEndian(kemIdentifier)
      try builder.appendUInt16BigEndian(UInt16(publicKey.count))
      try builder.append(publicKey)
      try builder.appendUInt16BigEndian(UInt16(cipherSuites.count * 4))
      var suiteIndex = 0
      while suiteIndex < cipherSuites.count {
        let suite = cipherSuites[suiteIndex]
        try builder.appendUInt16BigEndian(suite.kdfIdentifier)
        try builder.appendUInt16BigEndian(suite.aeadIdentifier)
        suiteIndex += 1
      }
      try builder.append(maximumNameLength)
      try builder.append(UInt8(publicName.count))
      try builder.append(publicName)
      try builder.appendUInt16BigEndian(UInt16(extensionByteCount))
      extensionIndex = 0
      while extensionIndex < extensions.count {
        let value = extensions[extensionIndex]
        try builder.appendUInt16BigEndian(value.type)
        try builder.appendUInt16BigEndian(UInt16(value.data.count))
        try builder.append(value.data.span)
        extensionIndex += 1
      }
      return builder.finish()
    } catch {
      throw .malformedConfig
    }
  }

  internal static func validatePublicName(_ name: Span<UInt8>) -> Bool {
    guard !name.isEmpty, name.count <= UInt8.max else { return false }
    var labelStart = 0
    var index = 0
    while index <= name.count {
      if index == name.count || name[index] == 0x2E {
        let labelCount = index - labelStart
        guard labelCount > 0, labelCount <= 63 else { return false }
        guard name[labelStart] != 0x2D, name[index - 1] != 0x2D else {
          return false
        }
        var labelIndex = labelStart
        while labelIndex < index {
          let byte = name[labelIndex]
          let isASCIIAlpha = (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
          let isDigit = (0x30...0x39).contains(byte)
          guard isASCIIAlpha || isDigit || byte == 0x2D else { return false }
          labelIndex += 1
        }
        guard index < name.count || !Self.isNumericHostLabel(name.extracting(labelStart..<index))
        else {
          return false
        }
        labelStart = index + 1
      }
      index += 1
    }
    return true
  }

  private static func isNumericHostLabel(_ label: Span<UInt8>) -> Bool {
    var decimal = true
    var index = 0
    while index < label.count {
      if !(0x30...0x39).contains(label[index]) { decimal = false }
      index += 1
    }
    if decimal { return true }
    guard label.count >= 2,
      label[0] == 0x30,
      label[1] == 0x78 || label[1] == 0x58
    else {
      return false
    }
    index = 2
    while index < label.count {
      let byte = label[index]
      let isHex =
        (0x30...0x39).contains(byte)
        || (0x41...0x46).contains(byte)
        || (0x61...0x66).contains(byte)
      if !isHex { return false }
      index += 1
    }
    return true
  }
}
