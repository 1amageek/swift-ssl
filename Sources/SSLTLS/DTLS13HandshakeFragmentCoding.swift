import SSLCore

public protocol DTLS13HandshakeFragmentCoding: Sendable {
  func fragments(
    in recordContent: Span<UInt8>
  ) throws(DTLS13HandshakeFragmentError) -> ContiguousArray<DTLS13HandshakeFragment>

  func appendFragment(
    tlsHandshakeMessage: Span<UInt8>,
    messageSequence: UInt16,
    fragmentOffset: Int,
    fragmentByteCount: Int,
    to output: inout ContiguousArray<UInt8>
  ) throws(DTLS13HandshakeFragmentError)
}
