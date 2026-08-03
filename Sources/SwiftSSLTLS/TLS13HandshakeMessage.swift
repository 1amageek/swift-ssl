import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

public struct TLS13ClientHello: Sendable, Hashable {
  public let random: OwnedBytes
  public let serverName: OwnedBytes?
  public let namedGroup: TLS13NamedGroup
  public let keyShare: OwnedBytes
  public let cipherSuite: TLSCipherSuite
  public let signatureSchemes: ContiguousArray<TLS13SignatureScheme>
  public let clientCertificateTypes: ContiguousArray<TLS13CertificateType>
  public let serverCertificateTypes: ContiguousArray<TLS13CertificateType>
  public let certificateCompressionAlgorithms:
    ContiguousArray<TLS13CertificateCompressionAlgorithm>
  public let delegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme>
  public let applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>
  public let transportParameters: OwnedBytes?
  public let connectionID: OwnedBytes?
  public let cookie: OwnedBytes?
  public let useSRTP: DTLSSRTPUseSRTPData?
  public let offersPostHandshakeAuthentication: Bool
  public let offersEarlyData: Bool
  public let preSharedKey: TLS13PreSharedKeyExtension?
}

public struct TLS13ServerHello: Sendable, Hashable {
  public let random: OwnedBytes
  public let namedGroup: TLS13NamedGroup
  public let keyShare: OwnedBytes
  public let cipherSuite: TLSCipherSuite
  public let selectedPreSharedKey: Bool
  public let connectionID: OwnedBytes?
}

public struct TLS13HelloRetryRequest: Sendable, Hashable {
  public let cipherSuite: TLSCipherSuite
  public let cookie: OwnedBytes
  public let echAcceptanceConfirmation: OwnedBytes?
}

/// Signature schemes permitted by the modern TLS 1.3 profile.
public enum TLS13SignatureScheme: UInt16, Sendable, Hashable {
  case ecdsaP256SHA256 = 0x0403
  case rsaPSSRSAESHA256 = 0x0804
  case ed25519 = 0x0807

  public func matches(
    _ subjectPublicKeyInfo: SubjectPublicKeyInfo
  ) -> Bool {
    switch self {
    case .ecdsaP256SHA256:
      return subjectPublicKeyInfo.isP256
    case .rsaPSSRSAESHA256:
      return subjectPublicKeyInfo.isRSA
    case .ed25519:
      return subjectPublicKeyInfo.isEd25519
    }
  }
}

public struct TLS13CertificateVerify: Sendable, Hashable {
  public let signatureScheme: TLS13SignatureScheme
  public let signature: OwnedBytes

  public init(
    signatureScheme: TLS13SignatureScheme,
    signature: consuming OwnedBytes
  ) {
    self.signatureScheme = signatureScheme
    self.signature = signature
  }
}

public enum TLS13HandshakeCodec {
  public static let clientHelloType: UInt8 = 1
  public static let serverHelloType: UInt8 = 2
  public static let endOfEarlyDataType: UInt8 = 5
  public static let encryptedExtensionsType: UInt8 = 8
  public static let certificateType: UInt8 = 11
  public static let certificateRequestType: UInt8 = 13
  public static let certificateVerifyType: UInt8 = 15
  public static let finishedType: UInt8 = 20
  public static let keyUpdateType: UInt8 = 24
  public static let compressedCertificateType: UInt8 = 25
  public static let messageHashType: UInt8 = 254

  private static var helloRetryRequestRandom: ContiguousArray<UInt8> {
    [
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
      0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
      0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]
  }

  public static func makeClientHello(
    random: Span<UInt8>,
    namedGroup: TLS13NamedGroup = .x25519,
    keyShare: Span<UInt8>,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    serverName: OwnedBytes? = nil,
    signatureSchemes: ContiguousArray<TLS13SignatureScheme> = [
      .ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519,
    ],
    clientCertificateTypes: ContiguousArray<TLS13CertificateType> = [],
    serverCertificateTypes: ContiguousArray<TLS13CertificateType> = [],
    certificateCompressionAlgorithms: ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    > = [],
    delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme> = [],
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    connectionID: Span<UInt8>? = nil,
    cookie: Span<UInt8>? = nil,
    useSRTP: DTLSSRTPUseSRTPData? = nil,
    offersPostHandshakeAuthentication: Bool = false,
    offersEarlyData: Bool = false,
    preSharedKey: TLS13PreSharedKeyExtension? = nil,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard random.count == 32,
      keyShare.count == namedGroup.clientShareByteCount
    else {
      throw .invalidKeyShare
    }
    guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
      throw .unsupportedCipherSuite(cipherSuite.rawValue)
    }
    guard !signatureSchemes.isEmpty else {
      throw .signatureFailure
    }
    guard !offersEarlyData || preSharedKey != nil else {
      throw .invalidPreSharedKey
    }
    guard useSRTP == nil || encoding == .dtls13 else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: 2 * 65_535,
      minimumCapacity: keyShare.count + 128
    )
    do {
      try body.appendUInt16BigEndian(encoding.legacyVersion)
      try body.append(random)
      try body.append(0)
      if encoding.includesLegacyCookie {
        try body.append(0)
      }
      try body.appendUInt16BigEndian(2)
      try body.appendUInt16BigEndian(cipherSuite.rawValue)
      try body.append(1)
      try body.append(0)
      var extensions = try Self.makeBuilder(
        maximumByteCount: 2 * 65_535,
        minimumCapacity: keyShare.count + 64
      )
      if let serverName {
        try appendServerName(to: &extensions, serverName: serverName.span)
      }
      try appendSignatureAlgorithms(
        to: &extensions,
        signatureSchemes: signatureSchemes
      )
      if !clientCertificateTypes.isEmpty {
        try appendCertificateTypes(
          to: &extensions,
          extensionType: TLS13CertificateType.clientExtensionType,
          certificateTypes: clientCertificateTypes
        )
      }
      if !serverCertificateTypes.isEmpty {
        try appendCertificateTypes(
          to: &extensions,
          extensionType: TLS13CertificateType.serverExtensionType,
          certificateTypes: serverCertificateTypes
        )
      }
      if !certificateCompressionAlgorithms.isEmpty {
        try appendCertificateCompressionAlgorithms(
          to: &extensions,
          algorithms: certificateCompressionAlgorithms
        )
      }
      if !delegatedCredentialAlgorithms.isEmpty {
        try appendDelegatedCredentialAlgorithms(
          to: &extensions,
          algorithms: delegatedCredentialAlgorithms
        )
      }
      if !applicationProtocols.isEmpty {
        try appendApplicationProtocols(
          to: &extensions,
          protocols: applicationProtocols
        )
      }
      try appendSupportedVersionsClient(to: &extensions, encoding: encoding)
      try appendSupportedGroups(to: &extensions, namedGroup: namedGroup)
      try appendClientKeyShare(
        to: &extensions,
        namedGroup: namedGroup,
        keyShare: keyShare
      )
      if let connectionID {
        try appendConnectionID(to: &extensions, connectionID: connectionID)
      }
      if let cookie {
        try appendCookie(to: &extensions, cookie: cookie)
      }
      if let transportParameters {
        guard transportParameters.count <= UInt16.max else {
          throw TLS13HandshakeError.malformedMessage
        }
        try extensions.appendUInt16BigEndian(0x0039)
        try extensions.appendUInt16BigEndian(UInt16(transportParameters.count))
        try extensions.append(transportParameters)
      }
      if let useSRTP {
        try appendUseSRTP(to: &extensions, data: useSRTP)
      }
      if offersPostHandshakeAuthentication {
        try extensions.appendUInt16BigEndian(0x0031)
        try extensions.appendUInt16BigEndian(0)
      }
      if offersEarlyData {
        try extensions.appendUInt16BigEndian(0x002A)
        try extensions.appendUInt16BigEndian(0)
      }
      if let preSharedKey {
        let value: OwnedBytes
        do {
          value = try preSharedKey.encodedValue()
        } catch {
          throw TLS13HandshakeError.invalidPreSharedKey
        }
        try extensions.appendUInt16BigEndian(TLS13PreSharedKeyExtension.extensionType)
        try extensions.appendUInt16BigEndian(UInt16(value.count))
        try extensions.append(value.span)
      }
      guard extensions.count <= UInt16.max else {
        throw TLS13HandshakeError.invalidPreSharedKey
      }
      try body.appendUInt16BigEndian(UInt16(extensions.count))
      try body.append(extensions.finish().span)
      return finish(type: Self.clientHelloType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseClientHello(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> TLS13ClientHello {
    let body = try readBody(message, expectedType: Self.clientHelloType)
    var cursor = ByteCursor(body)
    do {
      guard try cursor.readUInt16BigEndian() == encoding.legacyVersion else {
        throw TLS13HandshakeError.malformedMessage
      }
      let random = OwnedBytes(copying: try cursor.readSpan(count: 32))
      guard try cursor.readByte() == 0 else { throw TLS13HandshakeError.malformedMessage }
      if encoding.includesLegacyCookie {
        guard try cursor.readByte() == 0 else {
          throw TLS13HandshakeError.malformedMessage
        }
      }
      guard try cursor.readUInt16BigEndian() == 2,
        let cipherSuite = TLSCipherSuite(rawValue: try cursor.readUInt16BigEndian()),
        try cursor.readByte() == 1,
        try cursor.readByte() == 0
      else {
        throw TLS13HandshakeError.unsupportedCipherSuite(0)
      }
      let extensionsLength = Int(try cursor.readUInt16BigEndian())
      let extensions = try cursor.readSpan(count: extensionsLength)
      try cursor.requireFullyConsumed()
      let parsed = try parseClientExtensions(extensions, encoding: encoding)
      return TLS13ClientHello(
        random: random,
        serverName: parsed.serverName,
        namedGroup: parsed.namedGroup,
        keyShare: parsed.keyShare,
        cipherSuite: cipherSuite,
        signatureSchemes: parsed.signatureSchemes,
        clientCertificateTypes: parsed.clientCertificateTypes,
        serverCertificateTypes: parsed.serverCertificateTypes,
        certificateCompressionAlgorithms:
          parsed.certificateCompressionAlgorithms,
        delegatedCredentialAlgorithms:
          parsed.delegatedCredentialAlgorithms,
        applicationProtocols: parsed.applicationProtocols,
        transportParameters: parsed.transportParameters,
        connectionID: parsed.connectionID,
        cookie: parsed.cookie,
        useSRTP: parsed.useSRTP,
        offersPostHandshakeAuthentication:
          parsed.offersPostHandshakeAuthentication,
        offersEarlyData: parsed.offersEarlyData,
        preSharedKey: parsed.preSharedKey
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeServerHello(
    random: Span<UInt8>,
    namedGroup: TLS13NamedGroup = .x25519,
    keyShare: Span<UInt8>,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    selectedPreSharedKey: Bool = false,
    connectionID: Span<UInt8>? = nil,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard random.count == 32,
      keyShare.count == namedGroup.serverShareByteCount
    else {
      throw .invalidKeyShare
    }
    guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
      throw .unsupportedCipherSuite(cipherSuite.rawValue)
    }
    var body = try Self.makeBuilder(
      maximumByteCount: 2 * 65_535,
      minimumCapacity: keyShare.count + 100
    )
    do {
      try body.appendUInt16BigEndian(encoding.legacyVersion)
      try body.append(random)
      try body.append(0)
      try body.appendUInt16BigEndian(cipherSuite.rawValue)
      try body.append(0)
      var extensions = try Self.makeBuilder(
        maximumByteCount: 2 * 65_535,
        minimumCapacity: keyShare.count + 40
      )
      try appendSupportedVersionsServer(to: &extensions, encoding: encoding)
      try appendServerKeyShare(
        to: &extensions,
        namedGroup: namedGroup,
        keyShare: keyShare
      )
      if let connectionID {
        try appendConnectionID(to: &extensions, connectionID: connectionID)
      }
      if selectedPreSharedKey {
        try extensions.appendUInt16BigEndian(TLS13PreSharedKeyExtension.extensionType)
        try extensions.appendUInt16BigEndian(2)
        try extensions.appendUInt16BigEndian(0)
      }
      try body.appendUInt16BigEndian(UInt16(extensions.count))
      try body.append(extensions.finish().span)
      return finish(type: Self.serverHelloType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseServerHello(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> TLS13ServerHello {
    let body = try readBody(message, expectedType: Self.serverHelloType)
    var cursor = ByteCursor(body)
    do {
      guard try cursor.readUInt16BigEndian() == encoding.legacyVersion else {
        throw TLS13HandshakeError.malformedMessage
      }
      let random = OwnedBytes(copying: try cursor.readSpan(count: 32))
      guard try cursor.readByte() == 0 else { throw TLS13HandshakeError.malformedMessage }
      guard let cipherSuite = TLSCipherSuite(rawValue: try cursor.readUInt16BigEndian()),
        try cursor.readByte() == 0
      else {
        throw TLS13HandshakeError.unsupportedCipherSuite(0)
      }
      let extensionsLength = Int(try cursor.readUInt16BigEndian())
      let extensions = try cursor.readSpan(count: extensionsLength)
      try cursor.requireFullyConsumed()
      let parsed = try parseServerExtensions(extensions, encoding: encoding)
      return TLS13ServerHello(
        random: random,
        namedGroup: parsed.namedGroup,
        keyShare: parsed.keyShare,
        cipherSuite: cipherSuite,
        selectedPreSharedKey: parsed.selectedPreSharedKey,
        connectionID: parsed.connectionID
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeHelloRetryRequest(
    cookie: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    echAcceptanceConfirmation: Span<UInt8>? = nil,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
      throw .unsupportedCipherSuite(cipherSuite.rawValue)
    }
    guard echAcceptanceConfirmation == nil
      || echAcceptanceConfirmation?.count == ECHAcceptanceConfirmation.byteCount
    else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: 2 * 65_535,
      minimumCapacity: cookie.count + 64
    )
    do {
      try body.appendUInt16BigEndian(encoding.legacyVersion)
      try body.append(helloRetryRequestRandom.span)
      try body.append(0)
      try body.appendUInt16BigEndian(cipherSuite.rawValue)
      try body.append(0)
      var extensions = try Self.makeBuilder(
        maximumByteCount: Int(UInt16.max),
        minimumCapacity: cookie.count + 24
      )
      try appendSupportedVersionsServer(to: &extensions, encoding: encoding)
      try appendCookie(to: &extensions, cookie: cookie)
      if let echAcceptanceConfirmation {
        try extensions.appendUInt16BigEndian(
          ECHClientHelloCodec.encryptedClientHelloExtensionType
        )
        try extensions.appendUInt16BigEndian(
          UInt16(ECHAcceptanceConfirmation.byteCount)
        )
        try extensions.append(echAcceptanceConfirmation)
      }
      try body.appendUInt16BigEndian(UInt16(extensions.count))
      try body.append(extensions.finish().span)
      return finish(type: Self.serverHelloType, body: body.finish())
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseHelloRetryRequest(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> TLS13HelloRetryRequest {
    let body = try readBody(message, expectedType: Self.serverHelloType)
    var cursor = ByteCursor(body)
    do {
      guard try cursor.readUInt16BigEndian() == encoding.legacyVersion,
        ConstantTime.equal(
          try cursor.readSpan(count: 32),
          helloRetryRequestRandom.span
        ),
        try cursor.readByte() == 0,
        let cipherSuite = TLSCipherSuite(
          rawValue: try cursor.readUInt16BigEndian()
        ),
        try cursor.readByte() == 0
      else {
        throw TLS13HandshakeError.malformedMessage
      }
      let extensionsLength = Int(try cursor.readUInt16BigEndian())
      let extensions = try cursor.readSpan(count: extensionsLength)
      try cursor.requireFullyConsumed()
      var extensionCursor = ByteCursor(extensions)
      var sawSupportedVersions = false
      var cookie: OwnedBytes?
      var echConfirmation: OwnedBytes?
      var seenTypes = ContiguousArray<UInt16>()
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        let length = Int(try extensionCursor.readUInt16BigEndian())
        let value = try extensionCursor.readSpan(count: length)
        guard !seenTypes.contains(type) else {
          throw TLS13HandshakeError.malformedMessage
        }
        seenTypes.append(type)
        switch type {
        case 0x002B:
          guard value.count == 2,
            value[0] == UInt8(
              truncatingIfNeeded: encoding.negotiatedVersion >> 8
            ),
            value[1] == UInt8(
              truncatingIfNeeded: encoding.negotiatedVersion
            )
          else {
            throw TLS13HandshakeError.malformedMessage
          }
          sawSupportedVersions = true
        case 0x002C:
          cookie = try parseCookie(value)
        case ECHClientHelloCodec.encryptedClientHelloExtensionType:
          guard value.count == ECHAcceptanceConfirmation.byteCount else {
            throw TLS13HandshakeError.malformedMessage
          }
          echConfirmation = OwnedBytes(copying: value)
        default:
          throw TLS13HandshakeError.unsupportedExtension(type)
        }
      }
      guard sawSupportedVersions, let cookie else {
        throw TLS13HandshakeError.malformedMessage
      }
      return TLS13HelloRetryRequest(
        cipherSuite: cipherSuite,
        cookie: cookie,
        echAcceptanceConfirmation: echConfirmation
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  internal static func isHelloRetryRequest(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> Bool {
    let body = try readBody(message, expectedType: Self.serverHelloType)
    guard body.count >= 34 else { return false }
    return ConstantTime.equal(
      body.extracting(2..<34),
      helloRetryRequestRandom.span
    )
  }

  public static func makeEncryptedExtensions(
    applicationProtocol: TLS13ApplicationProtocol? = nil,
    transportParameters: Span<UInt8>? = nil,
    useSRTP: DTLSSRTPUseSRTPData? = nil,
    echRetryConfigurations: ECHConfigList? = nil,
    acceptsEarlyData: Bool = false,
    clientCertificateType: TLS13CertificateType? = nil,
    serverCertificateType: TLS13CertificateType? = nil,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let retryByteCount = echRetryConfigurations?.withEncodedBytes { $0.count } ?? 0
    guard retryByteCount <= UInt16.max - 4,
      (transportParameters?.count ?? 0) <= UInt16.max
    else {
      throw .malformedMessage
    }
    guard useSRTP == nil || encoding == .dtls13 else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: Int(UInt16.max) + 2,
      minimumCapacity: retryByteCount + 6
    )
    do {
      var extensions = try Self.makeBuilder(
        maximumByteCount: Int(UInt16.max),
        minimumCapacity: retryByteCount + (transportParameters?.count ?? 0) + 16
      )
      if let applicationProtocol {
        try appendApplicationProtocols(
          to: &extensions,
          protocols: [applicationProtocol]
        )
      }
      if let transportParameters {
        try extensions.appendUInt16BigEndian(0x0039)
        try extensions.appendUInt16BigEndian(UInt16(transportParameters.count))
        try extensions.append(transportParameters)
      }
      if let useSRTP {
        try appendUseSRTP(to: &extensions, data: useSRTP)
      }
      if acceptsEarlyData {
        try extensions.appendUInt16BigEndian(0x002A)
        try extensions.appendUInt16BigEndian(0)
      }
      if let clientCertificateType {
        try appendSelectedCertificateType(
          to: &extensions,
          extensionType: TLS13CertificateType.clientExtensionType,
          certificateType: clientCertificateType
        )
      }
      if let serverCertificateType {
        try appendSelectedCertificateType(
          to: &extensions,
          extensionType: TLS13CertificateType.serverExtensionType,
          certificateType: serverCertificateType
        )
      }
      if let echRetryConfigurations {
        try extensions.appendUInt16BigEndian(
          ECHClientHelloCodec.encryptedClientHelloExtensionType
        )
        try extensions.appendUInt16BigEndian(UInt16(retryByteCount))
        try echRetryConfigurations.withEncodedBytes {
          bytes throws(ByteError) in
          try extensions.append(bytes)
        }
      }
      guard extensions.count <= UInt16.max else {
        throw TLS13HandshakeError.malformedMessage
      }
      try body.appendUInt16BigEndian(UInt16(extensions.count))
      try body.append(extensions.finish().span)
      return finish(type: Self.encryptedExtensionsType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseEncryptedExtensions(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> TLS13EncryptedExtensions {
    let body = try readBody(message, expectedType: Self.encryptedExtensionsType)
    var cursor = ByteCursor(body)
    do {
      let extensionLength = Int(try cursor.readUInt16BigEndian())
      guard extensionLength == cursor.remainingCount else {
        throw TLS13HandshakeError.malformedMessage
      }
      var retryConfigurations: ECHConfigList?
      var applicationProtocol: TLS13ApplicationProtocol?
      var transportParameters: OwnedBytes?
      var useSRTP: DTLSSRTPUseSRTPData?
      var acceptsEarlyData = false
      var clientCertificateType: TLS13CertificateType?
      var serverCertificateType: TLS13CertificateType?
      var seenTypes = ContiguousArray<UInt16>()
      while !cursor.isAtEnd {
        let type = try cursor.readUInt16BigEndian()
        guard !seenTypes.contains(type) else {
          throw TLS13HandshakeError.malformedMessage
        }
        seenTypes.append(type)
        let byteCount = Int(try cursor.readUInt16BigEndian())
        let value = try cursor.readSpan(count: byteCount)
        switch type {
        case 0x0010:
          let protocols = try parseApplicationProtocols(value)
          guard protocols.count == 1 else {
            throw TLS13HandshakeError.malformedMessage
          }
          applicationProtocol = protocols[0]
        case 0x0039:
          transportParameters = OwnedBytes(copying: value)
        case DTLSSRTPUseSRTPData.extensionType:
          guard encoding == .dtls13 else {
            throw TLS13HandshakeError.malformedMessage
          }
          useSRTP = try parseUseSRTP(value)
        case 0x002A:
          guard value.isEmpty else {
            throw TLS13HandshakeError.malformedMessage
          }
          acceptsEarlyData = true
        case TLS13CertificateType.clientExtensionType:
          clientCertificateType = try parseSelectedCertificateType(value)
        case TLS13CertificateType.serverExtensionType:
          serverCertificateType = try parseSelectedCertificateType(value)
        case ECHClientHelloCodec.encryptedClientHelloExtensionType:
          do {
            retryConfigurations = try ECHConfigList(encoded: value)
          } catch {
            throw TLS13HandshakeError.malformedMessage
          }
        default:
          throw TLS13HandshakeError.unsupportedExtension(type)
        }
      }
      try cursor.requireFullyConsumed()
      return TLS13EncryptedExtensions(
        applicationProtocol: applicationProtocol,
        peerTransportParameters: transportParameters,
        useSRTP: useSRTP,
        echRetryConfigurations: retryConfigurations,
        acceptsEarlyData: acceptsEarlyData,
        clientCertificateType: clientCertificateType,
        serverCertificateType: serverCertificateType
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeEndOfEarlyData()
    throws(TLS13HandshakeError) -> OwnedBytes
  {
    finish(type: Self.endOfEarlyDataType, body: OwnedBytes())
  }

  public static func parseEndOfEarlyData(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) {
    let body = try readBody(message, expectedType: Self.endOfEarlyDataType)
    guard body.isEmpty else { throw .malformedMessage }
  }

  public static func makeCertificate(
    entries: borrowing ContiguousArray<TLS13CertificateEntry>,
    requestContext: Span<UInt8> = Span<UInt8>()
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard entries.count <= TLS13CertificateMessage.maximumCertificateCount,
      requestContext.count <= UInt8.max
    else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: 16 * 1024 * 1024,
      minimumCapacity: 512
    )
    do {
      try body.append(UInt8(requestContext.count))
      try body.append(requestContext)
      let listLengthOffset = body.count
      try body.appendUInt24BigEndian(0)
      var certificateList = try Self.makeBuilder(
        maximumByteCount: 16 * 1024 * 1024,
        minimumCapacity: 512
      )
      var entryIndex = 0
      while entryIndex < entries.count {
        let entry = entries[entryIndex]
        guard entryIndex == 0 || entry.delegatedCredential == nil else {
          throw TLS13HandshakeError.malformedMessage
        }
        try certificateList.appendUInt24BigEndian(
          UInt32(entry.certificate.count)
        )
        try certificateList.append(entry.certificate.span)
        let extensions = try makeCertificateEntryExtensions(entry)
        guard extensions.count <= UInt16.max else {
          throw TLS13HandshakeError.malformedMessage
        }
        try certificateList.appendUInt16BigEndian(UInt16(extensions.count))
        try certificateList.append(extensions.span)
        entryIndex += 1
      }
      let list = certificateList.finish()
      guard list.count <= 0x00FF_FFFF else {
        throw TLS13HandshakeError.malformedMessage
      }
      let prefix = body.finish()
      var finalBody = try Self.makeBuilder(
        maximumByteCount: 16 * 1024 * 1024,
        minimumCapacity: prefix.count + list.count
      )
      try finalBody.append(prefix.span.extracting(0..<listLengthOffset))
      try finalBody.appendUInt24BigEndian(UInt32(list.count))
      try finalBody.append(list.span)
      return finish(type: Self.certificateType, body: finalBody.finish())
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func makeCertificate(
    certificateDER: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let entry = try TLS13CertificateEntry(certificateDER: certificateDER)
    return try makeCertificate(entries: [entry])
  }

  public static func parseCertificateMessage(
    _ message: Span<UInt8>,
    certificateType: TLS13CertificateType = .x509
  ) throws(TLS13HandshakeError) -> TLS13CertificateMessage {
    let body = try readBody(message, expectedType: Self.certificateType)
    var cursor = ByteCursor(body)
    do {
      let contextLength = Int(try cursor.readByte())
      let context = OwnedBytes(
        copying: try cursor.readSpan(count: contextLength)
      )
      let listLength = Int(try cursor.readUInt24BigEndian())
      guard listLength == cursor.remainingCount else {
        throw TLS13HandshakeError.malformedMessage
      }
      let listBytes = try cursor.readSpan(count: listLength)
      try cursor.requireFullyConsumed()
      var list = ByteCursor(listBytes)
      var entries = ContiguousArray<TLS13CertificateEntry>()
      while !list.isAtEnd {
        guard entries.count < TLS13CertificateMessage.maximumCertificateCount else {
          throw TLS13HandshakeError.malformedMessage
        }
        let certificateLength = Int(try list.readUInt24BigEndian())
        guard certificateLength > 0 else {
          throw TLS13HandshakeError.malformedMessage
        }
        let certificate = CertificateBytes(
          copying: try list.readSpan(count: certificateLength)
        )
        let extensionLength = Int(try list.readUInt16BigEndian())
        let parsedExtensions = try parseCertificateEntryExtensions(
          try list.readSpan(count: extensionLength)
        )
        entries.append(
          TLS13CertificateEntry(
            certificate: certificate,
            stapledOCSPResponse: parsedExtensions.ocspResponse,
            signedCertificateTimestampList: parsedExtensions.sctList,
            delegatedCredential: parsedExtensions.delegatedCredential
          )
        )
      }
      var nonLeafIndex = 1
      while nonLeafIndex < entries.count {
        guard entries[nonLeafIndex].delegatedCredential == nil else {
          throw TLS13HandshakeError.malformedMessage
        }
        nonLeafIndex += 1
      }
      if certificateType == .rawPublicKey, !entries.isEmpty {
        guard entries.count == 1,
          entries[0].stapledOCSPResponse == nil,
          entries[0].signedCertificateTimestampList == nil,
          entries[0].delegatedCredential == nil
        else {
          throw TLS13HandshakeError.malformedMessage
        }
        let rawPublicKey = entries[0].certificate
        do {
          _ = try SubjectPublicKeyInfo(der: rawPublicKey.span)
        } catch {
          throw TLS13HandshakeError.certificateFailure
        }
      }
      return TLS13CertificateMessage(
        requestContext: context,
        entries: entries,
        certificateType: certificateType
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeCompressedCertificate(
    algorithm: TLS13CertificateCompressionAlgorithm,
    uncompressedCertificateMessageByteCount: Int,
    compressedCertificateMessage: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard uncompressedCertificateMessageByteCount > 0,
      uncompressedCertificateMessageByteCount <= 0x00FF_FFFF,
      !compressedCertificateMessage.isEmpty,
      compressedCertificateMessage.count <= 0x00FF_FFFF - 5
    else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: 0x00FF_FFFF,
      minimumCapacity: compressedCertificateMessage.count + 5
    )
    do {
      try body.appendUInt16BigEndian(algorithm.rawValue)
      try body.appendUInt24BigEndian(
        UInt32(uncompressedCertificateMessageByteCount)
      )
      try body.append(compressedCertificateMessage)
      return finish(
        type: compressedCertificateType,
        body: body.finish()
      )
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseCompressedCertificate(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) -> TLS13CompressedCertificateMessage {
    let body = try readBody(
      message,
      expectedType: compressedCertificateType
    )
    var cursor = ByteCursor(body)
    do {
      guard let algorithm = TLS13CertificateCompressionAlgorithm(
        rawValue: try cursor.readUInt16BigEndian()
      ) else {
        throw TLS13HandshakeError.malformedMessage
      }
      let uncompressedByteCount = Int(
        try cursor.readUInt24BigEndian()
      )
      guard uncompressedByteCount > 0, cursor.remainingCount > 0 else {
        throw TLS13HandshakeError.malformedMessage
      }
      let compressed = OwnedBytes(
        copying: try cursor.readSpan(count: cursor.remainingCount)
      )
      try cursor.requireFullyConsumed()
      return TLS13CompressedCertificateMessage(
        algorithm: algorithm,
        uncompressedByteCount: uncompressedByteCount,
        compressedCertificateMessage: compressed
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeCertificateRequest(
    requestContext: Span<UInt8> = Span<UInt8>(),
    signatureSchemes: ContiguousArray<TLS13SignatureScheme> = [.ed25519],
    certificateCompressionAlgorithms: ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    > = [],
    delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme> = []
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard requestContext.count <= UInt8.max else {
      throw .malformedMessage
    }
    var extensions = try Self.makeBuilder(
      maximumByteCount: Int(UInt16.max),
      minimumCapacity: 16
    )
    try appendSignatureAlgorithms(
      to: &extensions,
      signatureSchemes: signatureSchemes
    )
    if !certificateCompressionAlgorithms.isEmpty {
      try appendCertificateCompressionAlgorithms(
        to: &extensions,
        algorithms: certificateCompressionAlgorithms
      )
    }
    if !delegatedCredentialAlgorithms.isEmpty {
      try appendDelegatedCredentialAlgorithms(
        to: &extensions,
        algorithms: delegatedCredentialAlgorithms
      )
    }
    let encodedExtensions = extensions.finish()
    guard encodedExtensions.count <= UInt16.max else {
      throw .malformedMessage
    }
    var body = try Self.makeBuilder(
      maximumByteCount: Int(UInt8.max) + Int(UInt16.max) + 3,
      minimumCapacity: requestContext.count + encodedExtensions.count + 3
    )
    do {
      try body.append(UInt8(requestContext.count))
      try body.append(requestContext)
      try body.appendUInt16BigEndian(UInt16(encodedExtensions.count))
      try body.append(encodedExtensions.span)
      return finish(type: certificateRequestType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseCertificateRequest(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) -> TLS13CertificateRequest {
    let body = try readBody(message, expectedType: certificateRequestType)
    var cursor = ByteCursor(body)
    do {
      let contextByteCount = Int(try cursor.readByte())
      let requestContext = OwnedBytes(
        copying: try cursor.readSpan(count: contextByteCount)
      )
      let extensionsByteCount = Int(try cursor.readUInt16BigEndian())
      guard extensionsByteCount == cursor.remainingCount else {
        throw TLS13HandshakeError.malformedMessage
      }
      var extensions = ByteCursor(
        try cursor.readSpan(count: extensionsByteCount)
      )
      try cursor.requireFullyConsumed()
      var signatureSchemes: ContiguousArray<TLS13SignatureScheme>?
      var certificateCompressionAlgorithms =
        ContiguousArray<TLS13CertificateCompressionAlgorithm>()
      var delegatedCredentialAlgorithms =
        ContiguousArray<TLS13SignatureScheme>()
      var seenTypes = ContiguousArray<UInt16>()
      while !extensions.isAtEnd {
        let type = try extensions.readUInt16BigEndian()
        let valueByteCount = Int(try extensions.readUInt16BigEndian())
        let value = try extensions.readSpan(count: valueByteCount)
        guard !seenTypes.contains(type) else {
          throw TLS13HandshakeError.malformedMessage
        }
        seenTypes.append(type)
        if type == 0x000D {
          signatureSchemes = try parseSignatureAlgorithms(value)
        } else if type == TLS13CertificateCompressionAlgorithm.extensionType {
          certificateCompressionAlgorithms =
            try parseCertificateCompressionAlgorithms(value)
        } else if type == TLS13DelegatedCredential.extensionType {
          delegatedCredentialAlgorithms =
            try parseDelegatedCredentialAlgorithms(value)
        }
      }
      guard let signatureSchemes, !signatureSchemes.isEmpty else {
        throw TLS13HandshakeError.signatureFailure
      }
      return TLS13CertificateRequest(
        requestContext: requestContext,
        signatureSchemes: signatureSchemes,
        certificateCompressionAlgorithms: certificateCompressionAlgorithms,
        delegatedCredentialAlgorithms: delegatedCredentialAlgorithms
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeCertificateVerify(
    signature: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    try makeCertificateVerify(
      signatureScheme: .ed25519,
      signature: signature
    )
  }

  public static func makeCertificateVerify(
    signatureScheme: TLS13SignatureScheme,
    signature: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard !signature.isEmpty, signature.count <= UInt16.max else {
      throw .signatureFailure
    }
    var body = try Self.makeBuilder(
      maximumByteCount: Int(UInt16.max) + 4,
      minimumCapacity: signature.count + 4
    )
    do {
      try body.appendUInt16BigEndian(signatureScheme.rawValue)
      try body.appendUInt16BigEndian(UInt16(signature.count))
      try body.append(signature)
      return finish(type: Self.certificateVerifyType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseCertificateVerify(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let parsed = try parseCertificateVerifyWithScheme(message)
    guard parsed.signatureScheme == .ed25519,
      parsed.signature.count == 64
    else {
      throw .signatureFailure
    }
    return parsed.signature
  }

  public static func parseCertificateVerifyWithScheme(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) -> TLS13CertificateVerify {
    let body = try readBody(message, expectedType: Self.certificateVerifyType)
    var cursor = ByteCursor(body)
    do {
      guard
        let signatureScheme = TLS13SignatureScheme(
          rawValue: try cursor.readUInt16BigEndian()
        )
      else {
        throw TLS13HandshakeError.signatureFailure
      }
      let signatureLength = Int(try cursor.readUInt16BigEndian())
      guard signatureLength > 0 else { throw TLS13HandshakeError.signatureFailure }
      let signature = OwnedBytes(copying: try cursor.readSpan(count: signatureLength))
      try cursor.requireFullyConsumed()
      return TLS13CertificateVerify(
        signatureScheme: signatureScheme,
        signature: signature
      )
    } catch {
      throw .malformedMessage
    }
  }

  public static func makeFinished(
    verifyData: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard verifyData.count == 32 || verifyData.count == 48 else { throw .invalidFinished }
    return finish(type: Self.finishedType, body: OwnedBytes(copying: verifyData))
  }

  public static func parseFinished(
    _ message: Span<UInt8>,
    hashByteCount: Int
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let body = try readBody(message, expectedType: Self.finishedType)
    guard body.count == hashByteCount else { throw .invalidFinished }
    return OwnedBytes(copying: body)
  }

  public static func makeKeyUpdate(
    requestUpdate: Bool
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    var body = try Self.makeBuilder(maximumByteCount: 1, minimumCapacity: 1)
    do {
      try body.append(requestUpdate ? 1 : 0)
      return finish(type: Self.keyUpdateType, body: body.finish())
    } catch {
      throw .cryptographicFailure
    }
  }

  public static func parseKeyUpdate(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeError) -> Bool {
    let body = try readBody(message, expectedType: Self.keyUpdateType)
    guard body.count == 1 else { throw .malformedMessage }
    guard body[0] == 0 || body[0] == 1 else { throw .malformedMessage }
    return body[0] == 1
  }

  public static func splitMessages(
    _ bytes: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<OwnedBytes> {
    var cursor = ByteCursor(bytes)
    var result = ContiguousArray<OwnedBytes>()
    do {
      while !cursor.isAtEnd {
        guard cursor.remainingCount >= 4 else { throw TLS13HandshakeError.malformedMessage }
        let start = cursor.offset
        _ = try cursor.readByte()
        let length = Int(try cursor.readUInt24BigEndian())
        _ = try cursor.readSpan(count: length)
        let end = cursor.offset
        result.append(OwnedBytes(copying: bytes.extracting(start..<end)))
      }
      return result
    } catch {
      throw .malformedMessage
    }
  }

  internal static func clientHelloByAddingCookie(
    _ message: Span<UInt8>,
    cookie: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    _ = try parseClientHello(message, encoding: encoding)
    let body = try readBody(message, expectedType: Self.clientHelloType)
    var cursor = ByteCursor(body)
    do {
      _ = try cursor.readUInt16BigEndian()
      _ = try cursor.readSpan(count: 32)
      let sessionIDByteCount = Int(try cursor.readByte())
      _ = try cursor.readSpan(count: sessionIDByteCount)
      if encoding.includesLegacyCookie {
        let legacyCookieByteCount = Int(try cursor.readByte())
        guard legacyCookieByteCount == 0 else {
          throw TLS13HandshakeError.malformedMessage
        }
      }
      let cipherSuiteByteCount = Int(try cursor.readUInt16BigEndian())
      _ = try cursor.readSpan(count: cipherSuiteByteCount)
      let compressionByteCount = Int(try cursor.readByte())
      _ = try cursor.readSpan(count: compressionByteCount)
      let extensionsLengthOffset = cursor.offset
      let extensionsByteCount = Int(try cursor.readUInt16BigEndian())
      let extensions = try cursor.readSpan(count: extensionsByteCount)
      try cursor.requireFullyConsumed()

      var rewrittenExtensions = try Self.makeBuilder(
        maximumByteCount: Int(UInt16.max),
        minimumCapacity: extensions.count + cookie.count + 6
      )
      var extensionCursor = ByteCursor(extensions)
      var appendedCookie = false
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        let valueByteCount = Int(try extensionCursor.readUInt16BigEndian())
        let value = try extensionCursor.readSpan(count: valueByteCount)
        if type == 0x002C { continue }
        if type == TLS13PreSharedKeyExtension.extensionType,
          !appendedCookie
        {
          try appendCookie(to: &rewrittenExtensions, cookie: cookie)
          appendedCookie = true
        }
        try rewrittenExtensions.appendUInt16BigEndian(type)
        try rewrittenExtensions.appendUInt16BigEndian(UInt16(valueByteCount))
        try rewrittenExtensions.append(value)
      }
      if !appendedCookie {
        try appendCookie(to: &rewrittenExtensions, cookie: cookie)
      }
      let encodedExtensions = rewrittenExtensions.finish()
      var rewrittenBody = try Self.makeBuilder(
        maximumByteCount: 2 * 65_535,
        minimumCapacity: body.count + cookie.count + 6
      )
      try rewrittenBody.append(
        body.extracting(0..<extensionsLengthOffset)
      )
      try rewrittenBody.appendUInt16BigEndian(UInt16(encodedExtensions.count))
      try rewrittenBody.append(encodedExtensions.span)
      return finish(type: Self.clientHelloType, body: rewrittenBody.finish())
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  internal static func clientHelloByReplacingPSKBinders(
    _ message: Span<UInt8>,
    binders: consuming ContiguousArray<TLS13PSKBinder>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let parsed = try parseClientHello(message, encoding: encoding)
    guard let offered = parsed.preSharedKey,
      offered.identities.count == binders.count
    else {
      throw .invalidPreSharedKey
    }
    let replacement: OwnedBytes
    do {
      replacement = try TLS13PreSharedKeyExtension(
        identities: offered.identities,
        binders: binders
      ).encodedValue()
    } catch {
      throw .invalidPreSharedKey
    }
    let body = try readBody(message, expectedType: Self.clientHelloType)
    var cursor = ByteCursor(body)
    do {
      _ = try cursor.readUInt16BigEndian()
      _ = try cursor.readSpan(count: 32)
      _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      if encoding.includesLegacyCookie {
        _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      }
      _ = try cursor.readSpan(count: Int(try cursor.readUInt16BigEndian()))
      _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      let extensionsLengthOffset = cursor.offset
      let extensions = try cursor.readSpan(
        count: Int(try cursor.readUInt16BigEndian())
      )
      try cursor.requireFullyConsumed()
      var rewrittenExtensions = try Self.makeBuilder(
        maximumByteCount: Int(UInt16.max),
        minimumCapacity: extensions.count
      )
      var extensionCursor = ByteCursor(extensions)
      var replaced = false
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        let value = try extensionCursor.readSpan(
          count: Int(try extensionCursor.readUInt16BigEndian())
        )
        try rewrittenExtensions.appendUInt16BigEndian(type)
        if type == TLS13PreSharedKeyExtension.extensionType {
          guard !replaced else { throw TLS13HandshakeError.invalidPreSharedKey }
          try rewrittenExtensions.appendUInt16BigEndian(
            UInt16(replacement.count)
          )
          try rewrittenExtensions.append(replacement.span)
          replaced = true
        } else {
          try rewrittenExtensions.appendUInt16BigEndian(UInt16(value.count))
          try rewrittenExtensions.append(value)
        }
      }
      guard replaced else { throw TLS13HandshakeError.invalidPreSharedKey }
      let encodedExtensions = rewrittenExtensions.finish()
      var rewrittenBody = try Self.makeBuilder(
        maximumByteCount: 2 * 65_535,
        minimumCapacity: body.count
      )
      try rewrittenBody.append(
        body.extracting(0..<extensionsLengthOffset)
      )
      try rewrittenBody.appendUInt16BigEndian(UInt16(encodedExtensions.count))
      try rewrittenBody.append(encodedExtensions.span)
      return finish(type: Self.clientHelloType, body: rewrittenBody.finish())
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  internal static func clientHellosMatchForRetry(
    firstClientHello: Span<UInt8>,
    secondClientHello: Span<UInt8>,
    cookie: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> Bool {
    let expected = try clientHelloByAddingCookie(
      firstClientHello,
      cookie: cookie,
      encoding: encoding
    )
    let offeredExpected = try parseClientHello(
      expected.span,
      encoding: encoding
    )
    let expectedForComparison: OwnedBytes
    if offeredExpected.offersEarlyData {
      expectedForComparison = try clientHelloByRemovingEarlyData(
        expected.span,
        encoding: encoding
      )
    } else {
      expectedForComparison = expected
    }
    return try expectedForComparison.withBorrowedBytes {
      expectedBytes throws(TLS13HandshakeError) in
      let expectedParsed = try parseClientHello(
        expectedBytes,
        encoding: encoding
      )
      let secondParsed = try parseClientHello(
        secondClientHello,
        encoding: encoding
      )
      guard secondParsed.cookie == OwnedBytes(copying: cookie) else {
        return false
      }
      switch (expectedParsed.preSharedKey, secondParsed.preSharedKey) {
      case (.none, .none):
        return ConstantTime.equal(expectedBytes, secondClientHello)
      case (.some(let expectedPSK), .some(let secondPSK)):
        guard expectedPSK.identities.count == secondPSK.identities.count,
          expectedPSK.binders.count == secondPSK.binders.count
        else {
          return false
        }
        var index = 0
        while index < expectedPSK.identities.count {
          guard expectedPSK.identities[index].identity
            == secondPSK.identities[index].identity,
            expectedPSK.binders[index].value.count
              == secondPSK.binders[index].value.count
          else {
            return false
          }
          index += 1
        }
        let expectedWithoutPSK = try clientHelloByRemovingPreSharedKey(
          expectedBytes,
          encoding: encoding
        )
        let secondWithoutPSK = try clientHelloByRemovingPreSharedKey(
          secondClientHello,
          encoding: encoding
        )
        return ConstantTime.equal(
          expectedWithoutPSK.span,
          secondWithoutPSK.span
        )
      case (.none, .some), (.some, .none):
        return false
      }
    }
  }

  private static func clientHelloByRemovingPreSharedKey(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    try clientHelloByRemovingExtension(
      message,
      extensionType: TLS13PreSharedKeyExtension.extensionType,
      failure: .invalidPreSharedKey,
      encoding: encoding
    )
  }

  internal static func clientHelloByRemovingEarlyData(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    try clientHelloByRemovingExtension(
      message,
      extensionType: TLS13NewSessionTicket.earlyDataExtensionType,
      failure: .malformedMessage,
      encoding: encoding
    )
  }

  private static func clientHelloByRemovingExtension(
    _ message: Span<UInt8>,
    extensionType: UInt16,
    failure: TLS13HandshakeError,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let body = try readBody(message, expectedType: Self.clientHelloType)
    var cursor = ByteCursor(body)
    do {
      _ = try cursor.readUInt16BigEndian()
      _ = try cursor.readSpan(count: 32)
      _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      if encoding.includesLegacyCookie {
        _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      }
      _ = try cursor.readSpan(count: Int(try cursor.readUInt16BigEndian()))
      _ = try cursor.readSpan(count: Int(try cursor.readByte()))
      let extensionsLengthOffset = cursor.offset
      let extensions = try cursor.readSpan(
        count: Int(try cursor.readUInt16BigEndian())
      )
      try cursor.requireFullyConsumed()

      var rewrittenExtensions = try Self.makeBuilder(
        maximumByteCount: Int(UInt16.max),
        minimumCapacity: extensions.count
      )
      var extensionCursor = ByteCursor(extensions)
      var removed = false
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        let value = try extensionCursor.readSpan(
          count: Int(try extensionCursor.readUInt16BigEndian())
        )
        if type == extensionType {
          guard !removed else { throw failure }
          removed = true
          continue
        }
        try rewrittenExtensions.appendUInt16BigEndian(type)
        try rewrittenExtensions.appendUInt16BigEndian(UInt16(value.count))
        try rewrittenExtensions.append(value)
      }
      guard removed else { throw failure }
      let encodedExtensions = rewrittenExtensions.finish()
      var rewrittenBody = try Self.makeBuilder(
        maximumByteCount: 2 * 65_535,
        minimumCapacity: body.count
      )
      try rewrittenBody.append(body.extracting(0..<extensionsLengthOffset))
      try rewrittenBody.appendUInt16BigEndian(UInt16(encodedExtensions.count))
      try rewrittenBody.append(encodedExtensions.span)
      return finish(type: Self.clientHelloType, body: rewrittenBody.finish())
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  /// Returns the RFC 8446 binder transcript input while preserving the
  /// original ClientHello header, extension order, and unknown extensions.
  /// The pre_shared_key extension is already required to be last by
  /// `parseClientHello`, so removing its binders vector produces the exact
  /// ClientHello prefix defined by Section 4.2.11.2.
  internal static func truncatedClientHelloForBinder(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    let preSharedKey = try preSharedKeyForBinderTruncation(
      message,
      encoding: encoding
    )
    var bindersByteCount = 0
    for binder in preSharedKey.binders {
      let (nextCount, overflow) = bindersByteCount.addingReportingOverflow(
        1 + binder.value.count
      )
      guard !overflow else { throw .invalidPreSharedKey }
      bindersByteCount = nextCount
    }
    let removedByteCount = 2 + bindersByteCount
    guard removedByteCount <= message.count else {
      throw .invalidPreSharedKey
    }
    return OwnedBytes(
      copying: message.extracting(0..<(message.count - removedByteCount))
    )
  }

  /// Locates the final pre_shared_key extension without applying this
  /// package's cipher-suite and key-share negotiation policy. Binder
  /// truncation is a wire-format operation and must accept any structurally
  /// valid ClientHello, including a peer offering multiple cipher suites.
  private static func preSharedKeyForBinderTruncation(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> TLS13PreSharedKeyExtension {
    let body = try readBody(message, expectedType: Self.clientHelloType)
    var cursor = ByteCursor(body)
    do {
      _ = try cursor.readUInt16BigEndian()
      _ = try cursor.readSpan(count: 32)
      let sessionIDByteCount = Int(try cursor.readByte())
      _ = try cursor.readSpan(count: sessionIDByteCount)
      if encoding.includesLegacyCookie {
        let cookieByteCount = Int(try cursor.readByte())
        _ = try cursor.readSpan(count: cookieByteCount)
      }
      let cipherSuitesByteCount = Int(try cursor.readUInt16BigEndian())
      guard cipherSuitesByteCount >= 2, cipherSuitesByteCount.isMultiple(of: 2) else {
        throw TLS13HandshakeError.malformedMessage
      }
      _ = try cursor.readSpan(count: cipherSuitesByteCount)
      let compressionMethodsByteCount = Int(try cursor.readByte())
      guard compressionMethodsByteCount > 0 else {
        throw TLS13HandshakeError.malformedMessage
      }
      _ = try cursor.readSpan(count: compressionMethodsByteCount)
      let extensionsByteCount = Int(try cursor.readUInt16BigEndian())
      let extensions = try cursor.readSpan(count: extensionsByteCount)
      try cursor.requireFullyConsumed()

      var extensionCursor = ByteCursor(extensions)
      while !extensionCursor.isAtEnd {
        let type = try extensionCursor.readUInt16BigEndian()
        let valueByteCount = Int(try extensionCursor.readUInt16BigEndian())
        let value = try extensionCursor.readSpan(count: valueByteCount)
        guard
          type != TLS13PreSharedKeyExtension.extensionType
            || extensionCursor.isAtEnd
        else {
          throw TLS13HandshakeError.invalidPreSharedKey
        }
        if type == TLS13PreSharedKeyExtension.extensionType {
          do {
            return try TLS13PreSharedKeyExtension.parse(value)
          } catch {
            throw TLS13HandshakeError.invalidPreSharedKey
          }
        }
      }
      throw TLS13HandshakeError.invalidPreSharedKey
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func finish(type: UInt8, body: OwnedBytes) -> OwnedBytes {
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(4 + body.count)
    output.append(type)
    output.append(UInt8(truncatingIfNeeded: body.count >> 16))
    output.append(UInt8(truncatingIfNeeded: body.count >> 8))
    output.append(UInt8(truncatingIfNeeded: body.count))
    var bodyIndex = 0
    while bodyIndex < body.count {
      output.append(body[bodyIndex])
      bodyIndex += 1
    }
    return OwnedBytes(consuming: output)
  }

  private static func readBody(
    _ message: Span<UInt8>,
    expectedType: UInt8
  ) throws(TLS13HandshakeError) -> Span<UInt8> {
    guard message.count >= 4, message[0] == expectedType else {
      throw .unexpectedMessage(type: message.isEmpty ? 0 : message[0])
    }
    let length = (Int(message[1]) << 16) | (Int(message[2]) << 8) | Int(message[3])
    guard length == message.count - 4 else { throw .malformedMessage }
    return message.extracting(4..<message.count)
  }

  private static func appendSupportedVersionsClient(
    to builder: inout ByteBuilder,
    encoding: TLS13HandshakeEncoding
  )
    throws(ByteError)
  {
    try builder.appendUInt16BigEndian(0x002B)
    try builder.appendUInt16BigEndian(3)
    try builder.append(2)
    try builder.appendUInt16BigEndian(encoding.negotiatedVersion)
  }

  private static func appendSignatureAlgorithms(
    to builder: inout ByteBuilder,
    signatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>
  ) throws(TLS13HandshakeError) {
    guard !signatureSchemes.isEmpty,
      signatureSchemes.count <= Int(UInt16.max) / 2
    else {
      throw .signatureFailure
    }
    var seen = ContiguousArray<TLS13SignatureScheme>()
    seen.reserveCapacity(signatureSchemes.count)
    var index = 0
    while index < signatureSchemes.count {
      let scheme = signatureSchemes[index]
      guard !seen.contains(scheme) else {
        throw .signatureFailure
      }
      seen.append(scheme)
      index += 1
    }
    do {
      let listByteCount = signatureSchemes.count * 2
      try builder.appendUInt16BigEndian(0x000D)
      try builder.appendUInt16BigEndian(UInt16(listByteCount + 2))
      try builder.appendUInt16BigEndian(UInt16(listByteCount))
      index = 0
      while index < signatureSchemes.count {
        try builder.appendUInt16BigEndian(
          signatureSchemes[index].rawValue
        )
        index += 1
      }
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func appendCertificateTypes(
    to builder: inout ByteBuilder,
    extensionType: UInt16,
    certificateTypes: ContiguousArray<TLS13CertificateType>
  ) throws(ByteError) {
    guard !certificateTypes.isEmpty,
      certificateTypes.count <= Int(UInt8.max)
    else {
      throw .capacityExceeded(
        limit: Int(UInt8.max),
        attempted: certificateTypes.count
      )
    }
    var seen = ContiguousArray<TLS13CertificateType>()
    for certificateType in certificateTypes {
      guard !seen.contains(certificateType) else {
        throw .capacityExceeded(
          limit: certificateTypes.count - 1,
          attempted: certificateTypes.count
        )
      }
      seen.append(certificateType)
    }
    try builder.appendUInt16BigEndian(extensionType)
    try builder.appendUInt16BigEndian(UInt16(certificateTypes.count + 1))
    try builder.append(UInt8(certificateTypes.count))
    for certificateType in certificateTypes {
      try builder.append(certificateType.rawValue)
    }
  }

  private static func appendCertificateCompressionAlgorithms(
    to builder: inout ByteBuilder,
    algorithms: borrowing ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    >
  ) throws(TLS13HandshakeError) {
    guard !algorithms.isEmpty,
      algorithms.count <= Int(UInt8.max) / 2
    else {
      throw .malformedMessage
    }
    var seen = ContiguousArray<TLS13CertificateCompressionAlgorithm>()
    seen.reserveCapacity(algorithms.count)
    var index = 0
    while index < algorithms.count {
      guard !seen.contains(algorithms[index]) else {
        throw .malformedMessage
      }
      seen.append(algorithms[index])
      index += 1
    }
    do {
      let listByteCount = algorithms.count * 2
      try builder.appendUInt16BigEndian(
        TLS13CertificateCompressionAlgorithm.extensionType
      )
      try builder.appendUInt16BigEndian(UInt16(listByteCount + 1))
      try builder.append(UInt8(listByteCount))
      index = 0
      while index < algorithms.count {
        try builder.appendUInt16BigEndian(algorithms[index].rawValue)
        index += 1
      }
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func appendDelegatedCredentialAlgorithms(
    to builder: inout ByteBuilder,
    algorithms: borrowing ContiguousArray<TLS13SignatureScheme>
  ) throws(TLS13HandshakeError) {
    guard !algorithms.isEmpty,
      algorithms.count <= Int(UInt16.max) / 2
    else {
      throw .signatureFailure
    }
    var seen = ContiguousArray<TLS13SignatureScheme>()
    seen.reserveCapacity(algorithms.count)
    var index = 0
    while index < algorithms.count {
      guard algorithms[index] == .ecdsaP256SHA256
        || algorithms[index] == .ed25519,
        !seen.contains(algorithms[index])
      else {
        throw .signatureFailure
      }
      seen.append(algorithms[index])
      index += 1
    }
    do {
      let listByteCount = algorithms.count * 2
      try builder.appendUInt16BigEndian(
        TLS13DelegatedCredential.extensionType
      )
      try builder.appendUInt16BigEndian(UInt16(listByteCount + 2))
      try builder.appendUInt16BigEndian(UInt16(listByteCount))
      index = 0
      while index < algorithms.count {
        try builder.appendUInt16BigEndian(algorithms[index].rawValue)
        index += 1
      }
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func appendSelectedCertificateType(
    to builder: inout ByteBuilder,
    extensionType: UInt16,
    certificateType: TLS13CertificateType
  ) throws(ByteError) {
    try builder.appendUInt16BigEndian(extensionType)
    try builder.appendUInt16BigEndian(1)
    try builder.append(certificateType.rawValue)
  }

  private static func appendApplicationProtocols(
    to builder: inout ByteBuilder,
    protocols: borrowing ContiguousArray<TLS13ApplicationProtocol>
  ) throws(TLS13HandshakeError) {
    guard !protocols.isEmpty else {
      throw .malformedMessage
    }
    var listByteCount = 0
    var index = 0
    while index < protocols.count {
      var comparisonIndex = index + 1
      while comparisonIndex < protocols.count {
        guard protocols[index] != protocols[comparisonIndex] else {
          throw .malformedMessage
        }
        comparisonIndex += 1
      }
      let (nextCount, overflow) = listByteCount.addingReportingOverflow(
        1 + protocols[index].byteCount
      )
      guard !overflow, nextCount <= Int(UInt16.max) - 2 else {
        throw .malformedMessage
      }
      listByteCount = nextCount
      index += 1
    }
    do {
      try builder.appendUInt16BigEndian(0x0010)
      try builder.appendUInt16BigEndian(UInt16(listByteCount + 2))
      try builder.appendUInt16BigEndian(UInt16(listByteCount))
      index = 0
      while index < protocols.count {
        try builder.append(UInt8(protocols[index].byteCount))
        try protocols[index].withIdentifierBytes {
          bytes throws(ByteError) in
          try builder.append(bytes)
        }
        index += 1
      }
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func appendServerName(
    to builder: inout ByteBuilder,
    serverName: Span<UInt8>
  ) throws(ByteError) {
    guard !serverName.isEmpty, serverName.count <= 253 else {
      throw .capacityExceeded(limit: 253, attempted: serverName.count)
    }
    var index = 0
    while index < serverName.count {
      guard serverName[index] > 0, serverName[index] < 0x80 else {
        throw .integerDoesNotFit(value: UInt64(serverName[index]), byteCount: 1)
      }
      index += 1
    }
    let nameListByteCount = 1 + 2 + serverName.count
    try builder.appendUInt16BigEndian(0x0000)
    try builder.appendUInt16BigEndian(UInt16(2 + nameListByteCount))
    try builder.appendUInt16BigEndian(UInt16(nameListByteCount))
    try builder.append(0)
    try builder.appendUInt16BigEndian(UInt16(serverName.count))
    try builder.append(serverName)
  }

  private static func appendSupportedVersionsServer(
    to builder: inout ByteBuilder,
    encoding: TLS13HandshakeEncoding
  )
    throws(ByteError)
  {
    try builder.appendUInt16BigEndian(0x002B)
    try builder.appendUInt16BigEndian(2)
    try builder.appendUInt16BigEndian(encoding.negotiatedVersion)
  }

  private static func makeCertificateEntryExtensions(
    _ entry: borrowing TLS13CertificateEntry
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    var builder = try Self.makeBuilder(
      maximumByteCount: Int(UInt16.max),
      minimumCapacity: 128
    )
    do {
      if let response = entry.stapledOCSPResponse {
        guard response.count <= Int(UInt16.max) - 4 else {
          throw TLS13HandshakeError.malformedMessage
        }
        try builder.appendUInt16BigEndian(0x0005)
        try builder.appendUInt16BigEndian(UInt16(response.count + 4))
        try builder.append(1)
        try builder.appendUInt24BigEndian(UInt32(response.count))
        try builder.append(response.span)
      }
      if let list = entry.signedCertificateTimestampList {
        guard list.count <= UInt16.max else {
          throw TLS13HandshakeError.malformedMessage
        }
        try builder.appendUInt16BigEndian(0x0012)
        try builder.appendUInt16BigEndian(UInt16(list.count))
        try builder.append(list.span)
      }
      if let delegatedCredential = entry.delegatedCredential {
        let encoded = try RFC9345TLS13DelegatedCredentialCodec().encode(
          delegatedCredential
        )
        guard encoded.count <= UInt16.max else {
          throw TLS13HandshakeError.malformedMessage
        }
        try builder.appendUInt16BigEndian(
          TLS13DelegatedCredential.extensionType
        )
        try builder.appendUInt16BigEndian(UInt16(encoded.count))
        try builder.append(encoded.span)
      }
      return builder.finish()
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func parseCertificateEntryExtensions(
    _ encoded: Span<UInt8>
  ) throws(TLS13HandshakeError) -> (
    ocspResponse: OwnedBytes?,
    sctList: OwnedBytes?,
    delegatedCredential: TLS13DelegatedCredential?
  ) {
    var cursor = ByteCursor(encoded)
    var ocspResponse: OwnedBytes?
    var sctList: OwnedBytes?
    var delegatedCredential: TLS13DelegatedCredential?
    do {
      while !cursor.isAtEnd {
        let type = try cursor.readUInt16BigEndian()
        let length = Int(try cursor.readUInt16BigEndian())
        let value = try cursor.readSpan(count: length)
        switch type {
        case 0x0005:
          guard ocspResponse == nil else {
            throw TLS13HandshakeError.malformedMessage
          }
          var status = ByteCursor(value)
          guard try status.readByte() == 1 else {
            throw TLS13HandshakeError.malformedMessage
          }
          let responseLength = Int(try status.readUInt24BigEndian())
          guard responseLength > 0,
            responseLength == status.remainingCount
          else {
            throw TLS13HandshakeError.malformedMessage
          }
          ocspResponse = OwnedBytes(
            copying: try status.readSpan(count: responseLength)
          )
          try status.requireFullyConsumed()
        case 0x0012:
          guard sctList == nil, !value.isEmpty else {
            throw TLS13HandshakeError.malformedMessage
          }
          do {
            _ = try SignedCertificateTimestampList(encoded: value)
          } catch {
            throw TLS13HandshakeError.malformedMessage
          }
          sctList = OwnedBytes(copying: value)
        case TLS13DelegatedCredential.extensionType:
          guard delegatedCredential == nil else {
            throw TLS13HandshakeError.malformedMessage
          }
          do {
            delegatedCredential = try RFC9345TLS13DelegatedCredentialCodec()
              .decode(value)
          } catch {
            throw TLS13HandshakeError.malformedMessage
          }
        default:
          throw TLS13HandshakeError.unsupportedExtension(type)
        }
      }
      return (ocspResponse, sctList, delegatedCredential)
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func appendSupportedGroups(
    to builder: inout ByteBuilder,
    namedGroup: TLS13NamedGroup
  ) throws(ByteError) {
    try builder.appendUInt16BigEndian(0x000A)
    try builder.appendUInt16BigEndian(4)
    try builder.appendUInt16BigEndian(2)
    try builder.appendUInt16BigEndian(namedGroup.rawValue)
  }

  private static func appendClientKeyShare(
    to builder: inout ByteBuilder,
    namedGroup: TLS13NamedGroup,
    keyShare: Span<UInt8>
  ) throws(ByteError) {
    let entryByteCount = 4 + keyShare.count
    try builder.appendUInt16BigEndian(0x0033)
    try builder.appendUInt16BigEndian(UInt16(2 + entryByteCount))
    try builder.appendUInt16BigEndian(UInt16(entryByteCount))
    try builder.appendUInt16BigEndian(namedGroup.rawValue)
    try builder.appendUInt16BigEndian(UInt16(keyShare.count))
    try builder.append(keyShare)
  }

  private static func appendServerKeyShare(
    to builder: inout ByteBuilder,
    namedGroup: TLS13NamedGroup,
    keyShare: Span<UInt8>
  ) throws(ByteError) {
    try builder.appendUInt16BigEndian(0x0033)
    try builder.appendUInt16BigEndian(UInt16(4 + keyShare.count))
    try builder.appendUInt16BigEndian(namedGroup.rawValue)
    try builder.appendUInt16BigEndian(UInt16(keyShare.count))
    try builder.append(keyShare)
  }

  private static func appendConnectionID(
    to builder: inout ByteBuilder,
    connectionID: Span<UInt8>
  ) throws(ByteError) {
    guard connectionID.count <= UInt8.max else {
      throw .capacityExceeded(limit: Int(UInt8.max), attempted: connectionID.count)
    }
    try builder.appendUInt16BigEndian(54)
    try builder.appendUInt16BigEndian(UInt16(connectionID.count + 1))
    try builder.append(UInt8(connectionID.count))
    try builder.append(connectionID)
  }

  private static func appendCookie(
    to builder: inout ByteBuilder,
    cookie: Span<UInt8>
  ) throws(ByteError) {
    guard !cookie.isEmpty, cookie.count <= Int(UInt16.max) - 2 else {
      throw .capacityExceeded(
        limit: Int(UInt16.max) - 2,
        attempted: cookie.count
      )
    }
    try builder.appendUInt16BigEndian(0x002C)
    try builder.appendUInt16BigEndian(UInt16(cookie.count + 2))
    try builder.appendUInt16BigEndian(UInt16(cookie.count))
    try builder.append(cookie)
  }

  private static func appendUseSRTP(
    to builder: inout ByteBuilder,
    data: DTLSSRTPUseSRTPData
  ) throws(ByteError) {
    let profileByteCount = data.protectionProfileIDs.count * 2
    let valueByteCount = 2 + profileByteCount + 1 + data.masterKeyIdentifier.count
    guard !data.protectionProfileIDs.isEmpty,
      profileByteCount <= UInt16.max,
      data.masterKeyIdentifier.count <= UInt8.max,
      valueByteCount <= UInt16.max
    else {
      throw .capacityExceeded(
        limit: Int(UInt16.max),
        attempted: valueByteCount
      )
    }
    try builder.appendUInt16BigEndian(DTLSSRTPUseSRTPData.extensionType)
    try builder.appendUInt16BigEndian(UInt16(valueByteCount))
    try builder.appendUInt16BigEndian(UInt16(profileByteCount))
    for profileID in data.protectionProfileIDs {
      try builder.appendUInt16BigEndian(profileID)
    }
    try builder.append(UInt8(data.masterKeyIdentifier.count))
    try builder.append(data.masterKeyIdentifier.span)
  }

  private static func parseUseSRTP(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> DTLSSRTPUseSRTPData {
    var cursor = ByteCursor(value)
    do {
      let profileByteCount = Int(try cursor.readUInt16BigEndian())
      guard profileByteCount > 0, profileByteCount.isMultiple(of: 2) else {
        throw TLS13HandshakeError.malformedMessage
      }
      let profileBytes = try cursor.readSpan(count: profileByteCount)
      var profileCursor = ByteCursor(profileBytes)
      var profileIDs = ContiguousArray<UInt16>()
      profileIDs.reserveCapacity(profileByteCount / 2)
      while !profileCursor.isAtEnd {
        profileIDs.append(try profileCursor.readUInt16BigEndian())
      }
      let masterKeyIdentifierByteCount = Int(try cursor.readByte())
      let masterKeyIdentifier = OwnedBytes(
        copying: try cursor.readSpan(count: masterKeyIdentifierByteCount)
      )
      try cursor.requireFullyConsumed()
      return DTLSSRTPUseSRTPData(
        protectionProfileIDs: profileIDs,
        masterKeyIdentifier: masterKeyIdentifier
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseClientExtensions(
    _ bytes: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> (
    serverName: OwnedBytes?,
    namedGroup: TLS13NamedGroup,
    keyShare: OwnedBytes,
    signatureSchemes: ContiguousArray<TLS13SignatureScheme>,
    clientCertificateTypes: ContiguousArray<TLS13CertificateType>,
    serverCertificateTypes: ContiguousArray<TLS13CertificateType>,
    certificateCompressionAlgorithms:
      ContiguousArray<TLS13CertificateCompressionAlgorithm>,
    delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme>,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: OwnedBytes?,
    connectionID: OwnedBytes?,
    cookie: OwnedBytes?,
    useSRTP: DTLSSRTPUseSRTPData?,
    offersPostHandshakeAuthentication: Bool,
    offersEarlyData: Bool,
    preSharedKey: TLS13PreSharedKeyExtension?
  ) {
    var cursor = ByteCursor(bytes)
    var supportedGroups = ContiguousArray<TLS13NamedGroup>()
    var serverName: OwnedBytes?
    var sawSupportedVersions = false
    var keyShare: OwnedBytes?
    var keyShareGroup: TLS13NamedGroup?
    var signatureSchemes: ContiguousArray<TLS13SignatureScheme>?
    var clientCertificateTypes = ContiguousArray<TLS13CertificateType>()
    var serverCertificateTypes = ContiguousArray<TLS13CertificateType>()
    var certificateCompressionAlgorithms =
      ContiguousArray<TLS13CertificateCompressionAlgorithm>()
    var delegatedCredentialAlgorithms =
      ContiguousArray<TLS13SignatureScheme>()
    var applicationProtocols = ContiguousArray<TLS13ApplicationProtocol>()
    var transportParameters: OwnedBytes?
    var connectionID: OwnedBytes?
    var cookie: OwnedBytes?
    var useSRTP: DTLSSRTPUseSRTPData?
    var offersPostHandshakeAuthentication = false
    var offersEarlyData = false
    var preSharedKey: TLS13PreSharedKeyExtension?
    var sawPreSharedKey = false
    var seenTypes = ContiguousArray<UInt16>()
    do {
      while !cursor.isAtEnd {
        let type = try cursor.readUInt16BigEndian()
        let length = Int(try cursor.readUInt16BigEndian())
        let value = try cursor.readSpan(count: length)
        guard !seenTypes.contains(type) else {
          throw TLS13HandshakeError.malformedMessage
        }
        seenTypes.append(type)
        guard !sawPreSharedKey else { throw TLS13HandshakeError.malformedMessage }
        switch type {
        case 0x0000:
          serverName = try parseServerName(value)
        case 0x000D:
          signatureSchemes = try parseSignatureAlgorithms(value)
        case TLS13CertificateType.clientExtensionType:
          clientCertificateTypes = try parseCertificateTypes(value)
        case TLS13CertificateType.serverExtensionType:
          serverCertificateTypes = try parseCertificateTypes(value)
        case TLS13CertificateCompressionAlgorithm.extensionType:
          certificateCompressionAlgorithms =
            try parseCertificateCompressionAlgorithms(value)
        case TLS13DelegatedCredential.extensionType:
          delegatedCredentialAlgorithms =
            try parseDelegatedCredentialAlgorithms(value)
        case 0x0010:
          applicationProtocols = try parseApplicationProtocols(value)
        case 0x000A:
          supportedGroups = try parseSupportedGroups(value)
        case 0x002B:
          guard value.count == 3, value[0] == 2,
            value[1] == UInt8(truncatingIfNeeded: encoding.negotiatedVersion >> 8),
            value[2] == UInt8(truncatingIfNeeded: encoding.negotiatedVersion)
          else {
            throw TLS13HandshakeError.malformedMessage
          }
          sawSupportedVersions = true
        case 0x0033:
          let parsed = try parseClientKeyShare(value)
          keyShareGroup = parsed.namedGroup
          keyShare = parsed.keyShare
        case 0x0039:
          transportParameters = OwnedBytes(copying: value)
        case 54:
          connectionID = try parseConnectionID(value)
        case 0x002C:
          cookie = try parseCookie(value)
        case DTLSSRTPUseSRTPData.extensionType:
          guard encoding == .dtls13 else {
            throw TLS13HandshakeError.malformedMessage
          }
          useSRTP = try parseUseSRTP(value)
        case 0x0031:
          guard value.isEmpty else {
            throw TLS13HandshakeError.malformedMessage
          }
          offersPostHandshakeAuthentication = true
        case 0x002A:
          guard value.isEmpty else {
            throw TLS13HandshakeError.malformedMessage
          }
          offersEarlyData = true
        case TLS13PreSharedKeyExtension.extensionType:
          preSharedKey = try TLS13PreSharedKeyExtension.parse(value)
          sawPreSharedKey = true
        default:
          continue
        }
      }
      guard sawSupportedVersions,
        let keyShareGroup,
        let keyShare,
        supportedGroups.contains(keyShareGroup)
      else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      guard let signatureSchemes, !signatureSchemes.isEmpty else {
        throw TLS13HandshakeError.signatureFailure
      }
      guard !offersEarlyData || preSharedKey != nil else {
        throw TLS13HandshakeError.invalidPreSharedKey
      }
      return (
        serverName,
        keyShareGroup,
        keyShare,
        signatureSchemes,
        clientCertificateTypes,
        serverCertificateTypes,
        certificateCompressionAlgorithms,
        delegatedCredentialAlgorithms,
        applicationProtocols,
        transportParameters,
        connectionID,
        cookie,
        useSRTP,
        offersPostHandshakeAuthentication,
        offersEarlyData,
        preSharedKey
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch let error as TLS13PSKError {
      _ = error
      throw .invalidPreSharedKey
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseServerName(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    var cursor = ByteCursor(value)
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount == cursor.remainingCount, listByteCount >= 4,
        try cursor.readByte() == 0
      else {
        throw TLS13HandshakeError.malformedMessage
      }
      let nameByteCount = Int(try cursor.readUInt16BigEndian())
      guard nameByteCount > 0, nameByteCount <= 253 else {
        throw TLS13HandshakeError.malformedMessage
      }
      let name = try cursor.readSpan(count: nameByteCount)
      try cursor.requireFullyConsumed()
      var index = 0
      while index < name.count {
        guard name[index] > 0, name[index] < 0x80 else {
          throw TLS13HandshakeError.malformedMessage
        }
        index += 1
      }
      return OwnedBytes(copying: name)
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseServerExtensions(
    _ bytes: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeError) -> (
    namedGroup: TLS13NamedGroup,
    keyShare: OwnedBytes,
    selectedPreSharedKey: Bool,
    connectionID: OwnedBytes?
  ) {
    var cursor = ByteCursor(bytes)
    var sawSupportedVersions = false
    var keyShare: OwnedBytes?
    var keyShareGroup: TLS13NamedGroup?
    var selectedPreSharedKey = false
    var connectionID: OwnedBytes?
    var seenTypes = ContiguousArray<UInt16>()
    do {
      while !cursor.isAtEnd {
        let type = try cursor.readUInt16BigEndian()
        let length = Int(try cursor.readUInt16BigEndian())
        let value = try cursor.readSpan(count: length)
        guard !seenTypes.contains(type) else {
          throw TLS13HandshakeError.malformedMessage
        }
        seenTypes.append(type)
        switch type {
        case 0x002B:
          guard value.count == 2,
            value[0] == UInt8(truncatingIfNeeded: encoding.negotiatedVersion >> 8),
            value[1] == UInt8(truncatingIfNeeded: encoding.negotiatedVersion)
          else {
            throw TLS13HandshakeError.malformedMessage
          }
          sawSupportedVersions = true
        case 0x0033:
          let parsed = try parseServerKeyShare(value)
          keyShareGroup = parsed.namedGroup
          keyShare = parsed.keyShare
        case 54:
          connectionID = try parseConnectionID(value)
        case TLS13PreSharedKeyExtension.extensionType:
          guard value.count == 2, value[0] == 0, value[1] == 0 else {
            throw TLS13HandshakeError.invalidPreSharedKey
          }
          guard !selectedPreSharedKey else {
            throw TLS13HandshakeError.invalidPreSharedKey
          }
          selectedPreSharedKey = true
        default:
          continue
        }
      }
      guard sawSupportedVersions,
        let keyShareGroup,
        let keyShare
      else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      return (keyShareGroup, keyShare, selectedPreSharedKey, connectionID)
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseConnectionID(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard !value.isEmpty, Int(value[0]) == value.count - 1 else {
      throw .malformedMessage
    }
    return OwnedBytes(copying: value.extracting(1..<value.count))
  }

  private static func parseCookie(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> OwnedBytes {
    guard value.count >= 3 else { throw .malformedMessage }
    let byteCount = Int(value[0]) << 8 | Int(value[1])
    guard byteCount > 0, byteCount == value.count - 2 else {
      throw .malformedMessage
    }
    return OwnedBytes(copying: value.extracting(2..<value.count))
  }

  private static func parseSupportedGroups(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<TLS13NamedGroup> {
    var cursor = ByteCursor(value)
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount == cursor.remainingCount,
        listByteCount >= 2,
        listByteCount.isMultiple(of: 2)
      else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      var groups = ContiguousArray<TLS13NamedGroup>()
      groups.reserveCapacity(listByteCount / 2)
      while !cursor.isAtEnd {
        if let group = TLS13NamedGroup(rawValue: try cursor.readUInt16BigEndian()) {
          if !groups.contains(group) {
            groups.append(group)
          }
        }
      }
      return groups
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseSignatureAlgorithms(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<TLS13SignatureScheme> {
    var cursor = ByteCursor(value)
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount == cursor.remainingCount,
        listByteCount >= 2,
        listByteCount.isMultiple(of: 2)
      else {
        throw TLS13HandshakeError.signatureFailure
      }
      var schemes = ContiguousArray<TLS13SignatureScheme>()
      schemes.reserveCapacity(listByteCount / 2)
      while !cursor.isAtEnd {
        let rawValue = try cursor.readUInt16BigEndian()
        if let scheme = TLS13SignatureScheme(rawValue: rawValue),
          !schemes.contains(scheme)
        {
          schemes.append(scheme)
        }
      }
      return schemes
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseDelegatedCredentialAlgorithms(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<TLS13SignatureScheme> {
    let parsed = try parseSignatureAlgorithms(value)
    var result = ContiguousArray<TLS13SignatureScheme>()
    result.reserveCapacity(parsed.count)
    for algorithm in parsed where algorithm == .ecdsaP256SHA256
      || algorithm == .ed25519
    {
      result.append(algorithm)
    }
    return result
  }

  private static func parseCertificateTypes(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<TLS13CertificateType> {
    var cursor = ByteCursor(value)
    do {
      let byteCount = Int(try cursor.readByte())
      guard byteCount > 0, byteCount == cursor.remainingCount else {
        throw TLS13HandshakeError.malformedMessage
      }
      var result = ContiguousArray<TLS13CertificateType>()
      while !cursor.isAtEnd {
        guard let certificateType = TLS13CertificateType(
          rawValue: try cursor.readByte()
        ), !result.contains(certificateType) else {
          throw TLS13HandshakeError.malformedMessage
        }
        result.append(certificateType)
      }
      return result
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseCertificateCompressionAlgorithms(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<
    TLS13CertificateCompressionAlgorithm
  > {
    var cursor = ByteCursor(value)
    do {
      let byteCount = Int(try cursor.readByte())
      guard byteCount > 0,
        byteCount == cursor.remainingCount,
        byteCount.isMultiple(of: 2)
      else {
        throw TLS13HandshakeError.malformedMessage
      }
      var result = ContiguousArray<TLS13CertificateCompressionAlgorithm>()
      result.reserveCapacity(byteCount / 2)
      while !cursor.isAtEnd {
        guard let algorithm = TLS13CertificateCompressionAlgorithm(
          rawValue: try cursor.readUInt16BigEndian()
        ), !result.contains(algorithm) else {
          throw TLS13HandshakeError.malformedMessage
        }
        result.append(algorithm)
      }
      return result
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseSelectedCertificateType(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> TLS13CertificateType {
    guard value.count == 1,
      let certificateType = TLS13CertificateType(rawValue: value[0])
    else {
      throw .malformedMessage
    }
    return certificateType
  }

  private static func parseApplicationProtocols(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> ContiguousArray<TLS13ApplicationProtocol> {
    var cursor = ByteCursor(value)
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount == cursor.remainingCount, listByteCount >= 2 else {
        throw TLS13HandshakeError.malformedMessage
      }
      var protocols = ContiguousArray<TLS13ApplicationProtocol>()
      while !cursor.isAtEnd {
        let byteCount = Int(try cursor.readByte())
        guard byteCount > 0 else {
          throw TLS13HandshakeError.malformedMessage
        }
        let value = try cursor.readSpan(count: byteCount)
        let applicationProtocol: TLS13ApplicationProtocol
        do {
          applicationProtocol = try TLS13ApplicationProtocol(identifier: value)
        } catch {
          throw TLS13HandshakeError.malformedMessage
        }
        guard !protocols.contains(applicationProtocol) else {
          throw TLS13HandshakeError.malformedMessage
        }
        protocols.append(applicationProtocol)
      }
      return protocols
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .malformedMessage
    }
  }

  private static func parseClientKeyShare(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> (
    namedGroup: TLS13NamedGroup,
    keyShare: OwnedBytes
  ) {
    var cursor = ByteCursor(value)
    do {
      let entriesByteCount = Int(try cursor.readUInt16BigEndian())
      guard entriesByteCount == cursor.remainingCount else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      let parsed = try parseKeyShareEntry(from: &cursor, client: true)
      try cursor.requireFullyConsumed()
      return parsed
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .invalidKeyShare
    }
  }

  private static func parseServerKeyShare(
    _ value: Span<UInt8>
  ) throws(TLS13HandshakeError) -> (
    namedGroup: TLS13NamedGroup,
    keyShare: OwnedBytes
  ) {
    var cursor = ByteCursor(value)
    do {
      let parsed = try parseKeyShareEntry(from: &cursor, client: false)
      try cursor.requireFullyConsumed()
      return parsed
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .invalidKeyShare
    }
  }

  private static func parseKeyShareEntry(
    from cursor: inout ByteCursor,
    client: Bool
  ) throws(TLS13HandshakeError) -> (
    namedGroup: TLS13NamedGroup,
    keyShare: OwnedBytes
  ) {
    do {
      guard
        let namedGroup = TLS13NamedGroup(
          rawValue: try cursor.readUInt16BigEndian()
        )
      else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      let keyShareByteCount = Int(try cursor.readUInt16BigEndian())
      let expectedByteCount =
        client
        ? namedGroup.clientShareByteCount
        : namedGroup.serverShareByteCount
      guard keyShareByteCount == expectedByteCount else {
        throw TLS13HandshakeError.invalidKeyShare
      }
      return (
        namedGroup,
        OwnedBytes(copying: try cursor.readSpan(count: keyShareByteCount))
      )
    } catch let error as TLS13HandshakeError {
      throw error
    } catch {
      throw .invalidKeyShare
    }
  }

  private static func makeBuilder(
    maximumByteCount: Int,
    minimumCapacity: Int
  ) throws(TLS13HandshakeError) -> ByteBuilder {
    do {
      return try ByteBuilder(
        maximumByteCount: maximumByteCount,
        minimumCapacity: minimumCapacity
      )
    } catch {
      throw .cryptographicFailure
    }
  }
}
