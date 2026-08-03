import SSLCore
import SSLCrypto
import SSLTLS

@main
enum ECHInteropValidationCommand {
  static func main() throws {
    guard CommandLine.arguments.count >= 2 else {
      throw ValidationError.invalidArguments
    }
    switch CommandLine.arguments[1] {
    case "verify-boringssl-client":
      guard CommandLine.arguments.count == 5 else {
        throw ValidationError.invalidArguments
      }
      try verifyBoringSSLClient(
        privateKey: try decodeHex(CommandLine.arguments[2]),
        configList: try decodeHex(CommandLine.arguments[3]),
        clientHello: try decodeHex(CommandLine.arguments[4])
      )
    case "make-swift-client":
      guard CommandLine.arguments.count == 3 else {
        throw ValidationError.invalidArguments
      }
      try makeSwiftClient(configList: try decodeHex(CommandLine.arguments[2]))
    default:
      throw ValidationError.invalidArguments
    }
  }

  private static func verifyBoringSSLClient(
    privateKey: ContiguousArray<UInt8>,
    configList: ContiguousArray<UInt8>,
    clientHello: ContiguousArray<UInt8>
  ) throws {
    let list = try ECHConfigList(encoded: configList.span)
    guard let config = list.configurations.first else {
      throw ValidationError.emptyConfigurationList
    }
    let serverKey = try X25519PrivateKey(bytes: privateKey.span)
    let serverConfiguration = try ECHServerConfiguration(
      config: config,
      privateKey: serverKey
    )
    var opener = try RFC9849ECHClientHelloOpener(configuration: serverConfiguration)
    let opened = try opener.open(clientHello.span)
    let innerServerName = try parseServerName(opened.innerClientHello.span)
    let outerServerName = try parseServerName(clientHello.span)
    guard innerServerName == ascii("origin.example"),
      outerServerName == ascii("public.example")
    else {
      throw ValidationError.unexpectedServerNames
    }
    print("boringssl-client/swift-server:accepted")
  }

  private static func makeSwiftClient(
    configList: ContiguousArray<UInt8>
  ) throws {
    let list = try ECHConfigList(encoded: configList.span)
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(from: list)
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: RepeatingEntropy(byte: 0x53)
    )
    let keyShare = ContiguousArray<UInt8>(repeating: 0x31, count: 32)
    let inner = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span,
      keyShare: keyShare.span,
      serverName: OwnedBytes(copying: ascii("origin.example").span)
    )
    let outer = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span,
      keyShare: keyShare.span,
      serverName: OwnedBytes(copying: ascii("public.example").span)
    )
    let offer = try sealer.seal(
      innerClientHello: inner.span,
      outerClientHello: outer.span
    )
    print(encodeHex(offer.outerClientHello.span))
  }

  private static func parseServerName(
    _ clientHello: Span<UInt8>
  ) throws -> ContiguousArray<UInt8> {
    var message = ByteCursor(clientHello)
    guard try message.readByte() == TLS13HandshakeCodec.clientHelloType else {
      throw ValidationError.malformedClientHello
    }
    let bodyByteCount = try message.readUInt24BigEndian()
    let body = try message.readSpan(count: Int(bodyByteCount))
    try message.requireFullyConsumed()
    var cursor = ByteCursor(body)
    guard try cursor.readUInt16BigEndian() == 0x0303 else {
      throw ValidationError.malformedClientHello
    }
    _ = try cursor.readSpan(count: 32)
    _ = try cursor.readSpan(count: Int(try cursor.readByte()))
    _ = try cursor.readSpan(count: Int(try cursor.readUInt16BigEndian()))
    _ = try cursor.readSpan(count: Int(try cursor.readByte()))
    var extensions = ByteCursor(
      try cursor.readSpan(count: Int(try cursor.readUInt16BigEndian()))
    )
    try cursor.requireFullyConsumed()
    while !extensions.isAtEnd {
      let type = try extensions.readUInt16BigEndian()
      let value = try extensions.readSpan(
        count: Int(try extensions.readUInt16BigEndian())
      )
      if type == 0 {
        var nameList = ByteCursor(value)
        var names = ByteCursor(
          try nameList.readSpan(count: Int(try nameList.readUInt16BigEndian()))
        )
        try nameList.requireFullyConsumed()
        guard try names.readByte() == 0 else {
          throw ValidationError.malformedClientHello
        }
        let name = try names.readSpan(
          count: Int(try names.readUInt16BigEndian())
        )
        try names.requireFullyConsumed()
        return copy(name)
      }
    }
    throw ValidationError.missingServerName
  }

  private static func decodeHex(_ value: String) throws -> ContiguousArray<UInt8> {
    let bytes = ContiguousArray(value.utf8)
    guard bytes.count.isMultiple(of: 2) else {
      throw ValidationError.invalidHexadecimal
    }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count / 2)
    var index = 0
    while index < bytes.count {
      guard let high = hexNibble(bytes[index]),
        let low = hexNibble(bytes[index + 1])
      else {
        throw ValidationError.invalidHexadecimal
      }
      result.append((high << 4) | low)
      index += 2
    }
    return result
  }

  private static func encodeHex(_ bytes: Span<UInt8>) -> String {
    let alphabet = ContiguousArray("0123456789abcdef".utf8)
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count * 2)
    var index = 0
    while index < bytes.count {
      result.append(alphabet[Int(bytes[index] >> 4)])
      result.append(alphabet[Int(bytes[index] & 0x0F)])
      index += 1
    }
    return String(decoding: result, as: UTF8.self)
  }

  private static func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39:
      byte - 0x30
    case 0x61...0x66:
      byte - 0x61 + 10
    default:
      nil
    }
  }

  private static func ascii(_ value: String) -> ContiguousArray<UInt8> {
    ContiguousArray(value.utf8)
  }

  private static func copy(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
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

private enum ValidationError: Error {
  case invalidArguments
  case invalidHexadecimal
  case emptyConfigurationList
  case malformedClientHello
  case missingServerName
  case unexpectedServerNames
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
