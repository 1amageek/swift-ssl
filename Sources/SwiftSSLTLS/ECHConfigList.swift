import SwiftSSLCore

/// An RFC 9849 ECHConfigList that retains one exact wire owner.
public struct ECHConfigList: Sendable, Hashable {
  public let configurations: ContiguousArray<ECHConfig>
  private let wireEncoding: OwnedBytes

  public init(encoded: Span<UInt8>) throws(ECHError) {
    var cursor = ByteCursor(encoded)
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount >= 4, listByteCount == cursor.remainingCount else {
        throw ECHError.malformedConfigList
      }
      let list = try cursor.readSpan(count: listByteCount)
      try cursor.requireFullyConsumed()
      var entries = ByteCursor(list)
      var parsed = ContiguousArray<ECHConfig>()
      while !entries.isAtEnd {
        let entryStart = entries.offset
        let version = try entries.readUInt16BigEndian()
        let contentsByteCount = Int(try entries.readUInt16BigEndian())
        let contents = try entries.readSpan(count: contentsByteCount)
        if version == ECHConfig.version {
          let raw = list.extracting(entryStart..<entries.offset)
          parsed.append(try Self.parseCurrentConfig(contents, raw: raw))
        }
      }
      configurations = parsed
      wireEncoding = OwnedBytes(copying: encoded)
    } catch let error as ECHError {
      throw error
    } catch {
      throw .malformedConfigList
    }
  }

  public init(configurations: ContiguousArray<ECHConfig>) throws(ECHError) {
    guard !configurations.isEmpty else { throw .malformedConfigList }
    var byteCount = 0
    var configIndex = 0
    while configIndex < configurations.count {
      let config = configurations[configIndex]
      let encodedCount = config.withEncodedBytes { $0.count }
      let (next, overflow) = byteCount.addingReportingOverflow(encodedCount)
      guard !overflow, next <= UInt16.max else { throw .malformedConfigList }
      byteCount = next
      configIndex += 1
    }
    guard byteCount >= 4 else { throw .malformedConfigList }
    do {
      var builder = try ByteBuilder(
        maximumByteCount: Int(UInt16.max) + 2,
        minimumCapacity: byteCount + 2
      )
      try builder.appendUInt16BigEndian(UInt16(byteCount))
      configIndex = 0
      while configIndex < configurations.count {
        let config = configurations[configIndex]
        try config.withEncodedBytes { bytes throws(ByteError) in
          try builder.append(bytes)
        }
        configIndex += 1
      }
      self.configurations = copy configurations
      wireEncoding = builder.finish()
    } catch {
      throw .malformedConfigList
    }
  }

  public borrowing func withEncodedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(wireEncoding.span)
  }

  private static func parseCurrentConfig(
    _ contents: Span<UInt8>,
    raw: Span<UInt8>
  ) throws(ECHError) -> ECHConfig {
    var cursor = ByteCursor(contents)
    do {
      let configID = try cursor.readByte()
      let kemIdentifier = try cursor.readUInt16BigEndian()
      let publicKeyByteCount = Int(try cursor.readUInt16BigEndian())
      guard publicKeyByteCount > 0 else { throw ECHError.malformedConfig }
      let publicKey = OwnedBytes(copying: try cursor.readSpan(count: publicKeyByteCount))
      let suiteByteCount = Int(try cursor.readUInt16BigEndian())
      guard suiteByteCount >= 4, suiteByteCount.isMultiple(of: 4) else {
        throw ECHError.malformedConfig
      }
      let suiteBytes = try cursor.readSpan(count: suiteByteCount)
      var suiteCursor = ByteCursor(suiteBytes)
      var suites = ContiguousArray<ECHCipherSuite>()
      suites.reserveCapacity(suiteByteCount / 4)
      while !suiteCursor.isAtEnd {
        suites.append(
          ECHCipherSuite(
            kdfIdentifier: try suiteCursor.readUInt16BigEndian(),
            aeadIdentifier: try suiteCursor.readUInt16BigEndian()
          ))
      }
      let maximumNameLength = try cursor.readByte()
      let publicNameByteCount = Int(try cursor.readByte())
      guard publicNameByteCount > 0 else { throw ECHError.malformedConfig }
      let publicName = OwnedBytes(copying: try cursor.readSpan(count: publicNameByteCount))
      let extensionByteCount = Int(try cursor.readUInt16BigEndian())
      let extensionBytes = try cursor.readSpan(count: extensionByteCount)
      try cursor.requireFullyConsumed()
      var extensionCursor = ByteCursor(extensionBytes)
      var extensions = ContiguousArray<ECHConfigExtension>()
      var seenTypes = ContiguousArray<UInt16>()
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        guard !seenTypes.contains(type) else {
          throw ECHError.duplicateConfigExtension(type)
        }
        seenTypes.append(type)
        let byteCount = Int(try extensionCursor.readUInt16BigEndian())
        extensions.append(
          ECHConfigExtension(
            type: type,
            data: try extensionCursor.readSpan(count: byteCount)
          ))
      }
      return ECHConfig(
        configID: configID,
        kemIdentifier: kemIdentifier,
        publicKey: publicKey,
        cipherSuites: suites,
        maximumNameLength: maximumNameLength,
        publicName: publicName,
        extensions: extensions,
        isPublicNameValid: ECHConfig.validatePublicName(publicName.span),
        wireEncoding: OwnedBytes(copying: raw)
      )
    } catch let error as ECHError {
      throw error
    } catch {
      throw .malformedConfig
    }
  }
}
