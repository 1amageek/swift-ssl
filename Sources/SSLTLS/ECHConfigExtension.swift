import SSLCore

/// An opaque extension carried by an RFC 9849 ECH configuration.
public struct ECHConfigExtension: Sendable, Hashable {
  public let type: UInt16
  public let data: OwnedBytes

  public init(type: UInt16, data: Span<UInt8>) {
    self.type = type
    self.data = OwnedBytes(copying: data)
  }

  public var isMandatory: Bool {
    type & 0x8000 != 0
  }
}
