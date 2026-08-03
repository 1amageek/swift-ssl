public struct DTLS13Acknowledgment: Sendable, Hashable {
  public let recordNumbers: ContiguousArray<DTLS13RecordNumber>

  public init(
    recordNumbers: consuming ContiguousArray<DTLS13RecordNumber>
  ) throws(DTLS13AcknowledgmentError) {
    var index = 1
    while index < recordNumbers.count {
      guard recordNumbers[index - 1] < recordNumbers[index] else {
        throw .recordNumbersNotStrictlyIncreasing
      }
      index += 1
    }
    self.recordNumbers = recordNumbers
  }
}
