import SSLCore

public struct RFC9147DTLS13AcknowledgmentCodec: DTLS13AcknowledgmentCoding, Sendable {
  public static let recordNumberByteCount = 16

  public init() {}

  public func parse(
    _ bytes: Span<UInt8>
  ) throws(DTLS13AcknowledgmentError) -> DTLS13Acknowledgment {
    var cursor = ByteCursor(bytes)
    do {
      let vectorByteCount = Int(try cursor.readUInt16BigEndian())
      guard vectorByteCount == cursor.remainingCount,
        vectorByteCount.isMultiple(of: Self.recordNumberByteCount)
      else {
        throw DTLS13AcknowledgmentError.malformedLength(vectorByteCount)
      }
      var recordNumbers = ContiguousArray<DTLS13RecordNumber>()
      recordNumbers.reserveCapacity(vectorByteCount / Self.recordNumberByteCount)
      while !cursor.isAtEnd {
        let epoch = try Self.readUInt64BigEndian(from: &cursor)
        let sequenceNumber = try Self.readUInt64BigEndian(from: &cursor)
        do {
          recordNumbers.append(
            try DTLS13RecordNumber(
              epoch: epoch,
              sequenceNumber: sequenceNumber
            )
          )
        } catch let error {
          throw DTLS13AcknowledgmentError.record(error)
        }
      }
      return try DTLS13Acknowledgment(recordNumbers: recordNumbers)
    } catch let error as DTLS13AcknowledgmentError {
      throw error
    } catch let error as ByteError {
      throw .byte(error)
    } catch {
      throw .malformedLength(bytes.count)
    }
  }

  public func encode(
    _ acknowledgment: DTLS13Acknowledgment
  ) throws(DTLS13AcknowledgmentError) -> OwnedBytes {
    let (vectorByteCount, overflow) = acknowledgment.recordNumbers.count
      .multipliedReportingOverflow(by: Self.recordNumberByteCount)
    guard !overflow, vectorByteCount <= UInt16.max else {
      throw .malformedLength(overflow ? Int.max : vectorByteCount)
    }
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(2 + vectorByteCount)
    output.append(UInt8(truncatingIfNeeded: vectorByteCount >> 8))
    output.append(UInt8(truncatingIfNeeded: vectorByteCount))
    for recordNumber in acknowledgment.recordNumbers {
      Self.appendUInt64BigEndian(recordNumber.epoch, to: &output)
      Self.appendUInt64BigEndian(recordNumber.sequenceNumber, to: &output)
    }
    return OwnedBytes(consuming: output)
  }

  private static func readUInt64BigEndian(
    from cursor: inout ByteCursor
  ) throws(ByteError) -> UInt64 {
    let bytes = try cursor.readSpan(count: 8)
    var value: UInt64 = 0
    var index = 0
    while index < bytes.count {
      value = (value << 8) | UInt64(bytes[index])
      index += 1
    }
    return value
  }

  private static func appendUInt64BigEndian(
    _ value: UInt64,
    to output: inout ContiguousArray<UInt8>
  ) {
    var shift = 56
    while shift >= 0 {
      output.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
      shift -= 8
    }
  }
}
