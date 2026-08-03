public struct DTLS13RecordNumber: Sendable, Hashable, Comparable {
  public let epoch: UInt64
  public let sequenceNumber: UInt64

  public init(
    epoch: UInt64,
    sequenceNumber: UInt64
  ) throws(DTLS13RecordError) {
    guard sequenceNumber <= DTLS13ReplayWindow.maximumSequenceNumber else {
      throw .invalidSequenceNumber(sequenceNumber)
    }
    self.epoch = epoch
    self.sequenceNumber = sequenceNumber
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.epoch != rhs.epoch {
      return lhs.epoch < rhs.epoch
    }
    return lhs.sequenceNumber < rhs.sequenceNumber
  }
}
