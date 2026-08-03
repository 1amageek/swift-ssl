import SwiftSSLCore

public struct DTLS13DatagramRecord: Sendable, Hashable {
  public enum Kind: Sendable, Hashable {
    case plaintext(DTLS13RecordContentType)
    case ciphertext(epochBits: UInt8)
  }

  public let kind: Kind
  public let bytes: ByteRange

  public init(kind: Kind, bytes: ByteRange) {
    self.kind = kind
    self.bytes = bytes
  }
}
