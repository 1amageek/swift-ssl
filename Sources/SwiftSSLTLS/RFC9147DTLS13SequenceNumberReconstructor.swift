public struct RFC9147DTLS13SequenceNumberReconstructor:
  DTLS13SequenceNumberReconstructing,
  Sendable
{
  public init() {}

  public func reconstruct(
    truncatedSequenceNumber: UInt64,
    bitCount: Int,
    highestAuthenticatedSequenceNumber: UInt64?
  ) throws(DTLS13RecordError) -> UInt64 {
    guard bitCount == 8 || bitCount == 16 else {
      throw .invalidTruncatedSequenceNumber(
        bitCount: bitCount,
        value: truncatedSequenceNumber
      )
    }
    let window = UInt64(1) << UInt64(bitCount)
    guard truncatedSequenceNumber < window else {
      throw .invalidTruncatedSequenceNumber(
        bitCount: bitCount,
        value: truncatedSequenceNumber
      )
    }
    let expected: UInt64
    if let highestAuthenticatedSequenceNumber {
      let (next, overflow) = highestAuthenticatedSequenceNumber.addingReportingOverflow(1)
      expected = overflow ? highestAuthenticatedSequenceNumber : next
    } else {
      expected = 0
    }
    let mask = window - 1
    var candidate = (expected & ~mask) | truncatedSequenceNumber
    let halfWindow = window / 2

    if candidate <= expected,
      expected - candidate >= halfWindow,
      candidate <= DTLS13ReplayWindow.maximumSequenceNumber - window
    {
      candidate += window
    } else if candidate > expected,
      candidate - expected > halfWindow,
      candidate >= window
    {
      candidate -= window
    }
    guard candidate <= DTLS13ReplayWindow.maximumSequenceNumber else {
      throw .invalidSequenceNumber(candidate)
    }
    return candidate
  }
}
