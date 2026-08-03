public protocol DTLS13SequenceNumberReconstructing: Sendable {
  func reconstruct(
    truncatedSequenceNumber: UInt64,
    bitCount: Int,
    highestAuthenticatedSequenceNumber: UInt64?
  ) throws(DTLS13RecordError) -> UInt64
}
