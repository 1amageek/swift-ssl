import SSLCore

/// Metadata for one DTLSPlaintext record borrowing bytes from its datagram.
public struct DTLS13PlaintextRecord: Sendable, Hashable {
  public let contentType: DTLS13RecordContentType
  public let recordNumber: DTLS13RecordNumber
  public let fragment: ByteRange

  public init(
    contentType: DTLS13RecordContentType,
    recordNumber: DTLS13RecordNumber,
    fragment: ByteRange
  ) {
    self.contentType = contentType
    self.recordNumber = recordNumber
    self.fragment = fragment
  }
}
