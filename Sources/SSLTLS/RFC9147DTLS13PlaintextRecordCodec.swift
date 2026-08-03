import SSLCore

public struct RFC9147DTLS13PlaintextRecordCodec: DTLS13PlaintextRecordCoding, Sendable {
  public static let headerByteCount = 13
  public static let maximumFragmentByteCount = 16_384
  public static let legacyRecordVersion: UInt16 = 0xFEFD

  public init() {}

  public func records(
    in datagram: Span<UInt8>
  ) throws(DTLS13RecordError) -> ContiguousArray<DTLS13PlaintextRecord> {
    var cursor = ByteCursor(datagram)
    var records = ContiguousArray<DTLS13PlaintextRecord>()
    do {
      while !cursor.isAtEnd {
        let rawContentType = try cursor.readByte()
        guard let contentType = DTLS13RecordContentType(rawValue: rawContentType) else {
          throw DTLS13RecordError.unsupportedContentType(rawContentType)
        }
        guard contentType != .applicationData else {
          throw DTLS13RecordError.unsupportedContentType(rawContentType)
        }
        let version = try cursor.readUInt16BigEndian()
        guard version == Self.legacyRecordVersion || (records.isEmpty && version == 0xFEFF) else {
          throw DTLS13RecordError.invalidLegacyVersion(version)
        }
        let epoch = try cursor.readUInt16BigEndian()
        guard epoch == 0 else {
          throw DTLS13RecordError.invalidEpoch(UInt64(epoch))
        }
        let sequenceNumber = try Self.readUInt48BigEndian(from: &cursor)
        let fragmentByteCount = Int(try cursor.readUInt16BigEndian())
        guard fragmentByteCount <= Self.maximumFragmentByteCount else {
          throw DTLS13RecordError.recordTooLarge(
            limit: Self.maximumFragmentByteCount,
            actual: fragmentByteCount
          )
        }
        let fragmentOffset = cursor.offset
        _ = try cursor.readSpan(count: fragmentByteCount)
        records.append(
          DTLS13PlaintextRecord(
            contentType: contentType,
            recordNumber: try DTLS13RecordNumber(
              epoch: 0,
              sequenceNumber: sequenceNumber
            ),
            fragment: try ByteRange(
              offset: fragmentOffset,
              count: fragmentByteCount
            )
          )
        )
      }
    } catch let error as DTLS13RecordError {
      throw error
    } catch let error as ByteError {
      throw .byte(error)
    } catch {
      throw .malformedRecord
    }
    return records
  }

  public func appendRecord(
    contentType: DTLS13RecordContentType,
    sequenceNumber: UInt64,
    fragment: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) throws(DTLS13RecordError) {
    guard contentType != .applicationData else {
      throw .unsupportedContentType(contentType.rawValue)
    }
    guard sequenceNumber <= DTLS13ReplayWindow.maximumSequenceNumber else {
      throw .invalidSequenceNumber(sequenceNumber)
    }
    guard fragment.count <= Self.maximumFragmentByteCount else {
      throw .recordTooLarge(
        limit: Self.maximumFragmentByteCount,
        actual: fragment.count
      )
    }
    let (requiredByteCount, overflow) = Self.headerByteCount.addingReportingOverflow(fragment.count)
    guard !overflow else { throw .malformedRecord }
    output.reserveCapacity(output.count + requiredByteCount)
    output.append(contentType.rawValue)
    output.append(0xFE)
    output.append(0xFD)
    output.append(0)
    output.append(0)
    Self.appendUInt48BigEndian(sequenceNumber, to: &output)
    output.append(UInt8(truncatingIfNeeded: fragment.count >> 8))
    output.append(UInt8(truncatingIfNeeded: fragment.count))
    Self.append(fragment, to: &output)
  }

  private static func readUInt48BigEndian(
    from cursor: inout ByteCursor
  ) throws(ByteError) -> UInt64 {
    let bytes = try cursor.readSpan(count: 6)
    var value: UInt64 = 0
    var index = 0
    while index < bytes.count {
      value = (value << 8) | UInt64(bytes[index])
      index += 1
    }
    return value
  }

  private static func appendUInt48BigEndian(
    _ value: UInt64,
    to output: inout ContiguousArray<UInt8>
  ) {
    var shift = 40
    while shift >= 0 {
      output.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
      shift -= 8
    }
  }

  private static func append(
    _ bytes: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < bytes.count {
      output.append(bytes[index])
      index += 1
    }
  }
}
