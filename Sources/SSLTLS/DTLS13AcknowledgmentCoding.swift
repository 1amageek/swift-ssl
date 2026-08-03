import SSLCore

public protocol DTLS13AcknowledgmentCoding: Sendable {
  func parse(
    _ bytes: Span<UInt8>
  ) throws(DTLS13AcknowledgmentError) -> DTLS13Acknowledgment

  func encode(
    _ acknowledgment: DTLS13Acknowledgment
  ) throws(DTLS13AcknowledgmentError) -> OwnedBytes
}
