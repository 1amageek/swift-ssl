import SSLCore

public protocol DTLS13HandshakeReassembling: Sendable {
  var nextReceiveSequence: UInt16 { get }
  var bufferedByteCount: Int { get }

  mutating func receive(
    _ fragment: DTLS13HandshakeFragment,
    from recordContent: Span<UInt8>
  ) throws(DTLS13HandshakeFragmentError)

  mutating func takeNextMessage() -> OwnedBytes?
}
