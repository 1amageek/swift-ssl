import SSLCore

/// Errors raised while encoding or decoding the WebRTC DTLS 1.2 extensions.
public enum DTLS12ExtensionError: Error, Sendable, Equatable {
  case malformed
  case duplicateExtension(UInt16)
  case invalidSRTPProfiles
  case invalidMKI
  case bytes(ByteError)
}

/// RFC 5764 SRTP protection-profile identifier.
public struct DTLS12SRTPProtectionProfile: RawRepresentable, Sendable, Hashable {
  public let rawValue: UInt16

  public init(rawValue: UInt16) {
    self.rawValue = rawValue
  }

  public static let aes128CMHMACSHA180 = Self(rawValue: 0x0001)
  public static let aes128CMHMACSHA132 = Self(rawValue: 0x0002)
  public static let nullHMACSHA180 = Self(rawValue: 0x0005)
  public static let nullHMACSHA132 = Self(rawValue: 0x0006)
}

/// The three security extensions required by the narrow WebRTC DTLS profile.
///
/// The value is an owned control-plane representation. Record payloads use the
/// scoped `Span` APIs in `DTLS12AESGCMRecordProtector`; this metadata is small
/// and is copied only at the handshake boundary.
public struct DTLS12SecurityExtensions: Sendable, Equatable {
  public static let useSRTPType: UInt16 = 0x000E
  public static let extendedMasterSecretType: UInt16 = 0x0017
  public static let renegotiationInfoType: UInt16 = 0xFF01

  public let protectionProfiles: [DTLS12SRTPProtectionProfile]
  public let mki: [UInt8]
  public let extendedMasterSecret: Bool
  public let secureRenegotiation: Bool

  public init(
    protectionProfiles: [DTLS12SRTPProtectionProfile],
    mki: [UInt8] = [],
    extendedMasterSecret: Bool = true,
    secureRenegotiation: Bool = true
  ) throws(DTLS12ExtensionError) {
    guard !protectionProfiles.isEmpty,
      protectionProfiles.count <= Int(UInt16.max) / 2 else {
      throw .invalidSRTPProfiles
    }
    var seen = Set<DTLS12SRTPProtectionProfile>()
    for profile in protectionProfiles {
      guard seen.insert(profile).inserted else { throw .invalidSRTPProfiles }
    }
    guard mki.count <= UInt8.max else { throw .invalidMKI }
    self.protectionProfiles = protectionProfiles
    self.mki = mki
    self.extendedMasterSecret = extendedMasterSecret
    self.secureRenegotiation = secureRenegotiation
  }

  /// Encodes the complete `extensions<2..2^16-1>` vector.
  public func encode() throws(DTLS12ExtensionError) -> OwnedBytes {
    do {
      var useSRTPBody = try ByteBuilder(maximumByteCount: Int(UInt16.max))
      let profileByteCount = protectionProfiles.count * 2
      try useSRTPBody.appendUInt16BigEndian(UInt16(profileByteCount))
      for profile in protectionProfiles {
        try useSRTPBody.appendUInt16BigEndian(profile.rawValue)
      }
      try useSRTPBody.append(UInt8(mki.count))
      try mki.withUnsafeBufferPointer { buffer throws(ByteError) in
        try useSRTPBody.append(Span(_unsafeElements: buffer))
      }

      var extensions = try ByteBuilder(maximumByteCount: Int(UInt16.max))
      try appendExtension(
        type: Self.useSRTPType,
        body: useSRTPBody.finish(),
        to: &extensions
      )
      if extendedMasterSecret {
        try appendExtension(type: Self.extendedMasterSecretType, body: OwnedBytes(), to: &extensions)
      }
      if secureRenegotiation {
        var body = try ByteBuilder(maximumByteCount: 1)
        try body.append(0)
        try appendExtension(type: Self.renegotiationInfoType, body: body.finish(), to: &extensions)
      }

      var result = try ByteBuilder(maximumByteCount: Int(UInt16.max))
      try result.appendUInt16BigEndian(UInt16(extensions.count))
      try extensions.finish().withBorrowedBytes { (bytes: Span<UInt8>) throws(ByteError) in
        try result.append(bytes)
      }
      return result.finish()
    } catch let error {
      throw .bytes(error)
    }
  }

  /// Decodes and validates a complete `extensions<2..2^16-1>` vector.
  public static func decode(_ bytes: Span<UInt8>) throws(DTLS12ExtensionError) -> Self {
    do {
      var outer = ByteCursor(bytes)
      let vectorLength = Int(try outer.readUInt16BigEndian())
      let vector = try outer.readSpan(count: vectorLength)
      try outer.requireFullyConsumed()
      var cursor = ByteCursor(vector)
      var profiles: [DTLS12SRTPProtectionProfile] = []
      var mki: [UInt8] = []
      var hasSRTP = false
      var hasEMS = false
      var hasRenegotiation = false
      while !cursor.isAtEnd {
        let type = try cursor.readUInt16BigEndian()
        let length = Int(try cursor.readUInt16BigEndian())
        let body = try cursor.readSpan(count: length)
        switch type {
        case Self.useSRTPType:
          guard !hasSRTP else { throw DTLS12ExtensionError.duplicateExtension(type) }
          hasSRTP = true
          var payload = ByteCursor(body)
          let profileLength = Int(try payload.readUInt16BigEndian())
          guard profileLength >= 2, profileLength.isMultiple(of: 2) else {
            throw DTLS12ExtensionError.invalidSRTPProfiles
          }
          let profileBytes = try payload.readSpan(count: profileLength)
          profiles.reserveCapacity(profileLength / 2)
          var profileCursor = ByteCursor(profileBytes)
          while !profileCursor.isAtEnd {
            profiles.append(.init(rawValue: try profileCursor.readUInt16BigEndian()))
          }
          let mkiLength = Int(try payload.readByte())
          let mkiBytes = try payload.readSpan(count: mkiLength)
          mki = mkiBytes.withUnsafeBytes { Array($0) }
          try payload.requireFullyConsumed()
        case Self.extendedMasterSecretType:
          guard !hasEMS, body.isEmpty else {
            throw hasEMS ? DTLS12ExtensionError.duplicateExtension(type) : .malformed
          }
          hasEMS = true
        case Self.renegotiationInfoType:
          guard !hasRenegotiation, body.count == 1, body[0] == 0 else {
            throw hasRenegotiation ? DTLS12ExtensionError.duplicateExtension(type) : .malformed
          }
          hasRenegotiation = true
        default:
          continue
        }
      }
      guard hasSRTP else { throw DTLS12ExtensionError.invalidSRTPProfiles }
      return try Self(
        protectionProfiles: profiles,
        mki: mki,
        extendedMasterSecret: hasEMS,
        secureRenegotiation: hasRenegotiation
      )
    } catch let error as DTLS12ExtensionError {
      throw error
    } catch let error as ByteError {
      throw .bytes(error)
    } catch {
      throw DTLS12ExtensionError.malformed
    }
  }

  private func appendExtension(
    type: UInt16,
    body: OwnedBytes,
    to builder: inout ByteBuilder
  ) throws(ByteError) {
    try builder.appendUInt16BigEndian(type)
    try builder.appendUInt16BigEndian(UInt16(body.count))
    try body.withBorrowedBytes { (bytes: Span<UInt8>) throws(ByteError) in
      try builder.append(bytes)
    }
  }
}
