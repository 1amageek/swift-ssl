import SwiftSSLCore

/// Metadata for one DTLSHandshake fragment borrowing its body from a record.
public struct DTLS13HandshakeFragment: Sendable, Hashable {
  public let messageType: UInt8
  public let messageByteCount: Int
  public let messageSequence: UInt16
  public let fragmentOffset: Int
  public let fragment: ByteRange

  public init(
    messageType: UInt8,
    messageByteCount: Int,
    messageSequence: UInt16,
    fragmentOffset: Int,
    fragment: ByteRange
  ) {
    self.messageType = messageType
    self.messageByteCount = messageByteCount
    self.messageSequence = messageSequence
    self.fragmentOffset = fragmentOffset
    self.fragment = fragment
  }
}
