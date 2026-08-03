import SwiftSSLCore

/// Locates consecutive plaintext and ciphertext records in one datagram.
public struct RFC9147DTLS13DatagramRecordFramer:
  DTLS13DatagramRecordFraming,
  Sendable
{
  public let expectedConnectionIDByteCount: Int

  public init(expectedConnectionIDByteCount: Int = 0) throws(DTLS13RecordError) {
    guard expectedConnectionIDByteCount >= 0,
      expectedConnectionIDByteCount <= UInt8.max
    else {
      throw .recordTooLarge(
        limit: Int(UInt8.max),
        actual: expectedConnectionIDByteCount
      )
    }
    self.expectedConnectionIDByteCount = expectedConnectionIDByteCount
  }

  public func records(
    in datagram: Span<UInt8>
  ) throws(DTLS13RecordError) -> ContiguousArray<DTLS13DatagramRecord> {
    var records = ContiguousArray<DTLS13DatagramRecord>()
    var offset = 0
    do {
      while offset < datagram.count {
        let firstByte = datagram[offset]
        let kind: DTLS13DatagramRecord.Kind
        let recordByteCount: Int
        if firstByte == DTLS13RecordContentType.alert.rawValue
          || firstByte == DTLS13RecordContentType.handshake.rawValue
          || firstByte == DTLS13RecordContentType.acknowledgment.rawValue
        {
          guard datagram.count - offset >= RFC9147DTLS13PlaintextRecordCodec.headerByteCount else {
            throw DTLS13RecordError.malformedRecord
          }
          let fragmentByteCount =
            (Int(datagram[offset + 11]) << 8)
            | Int(datagram[offset + 12])
          let (total, overflow) = RFC9147DTLS13PlaintextRecordCodec.headerByteCount
            .addingReportingOverflow(fragmentByteCount)
          guard !overflow, total <= datagram.count - offset else {
            throw DTLS13RecordError.malformedRecord
          }
          kind = .plaintext(DTLS13RecordContentType(rawValue: firstByte)!)
          recordByteCount = total
        } else {
          guard firstByte & 0xE0 == 0x20 else {
            throw DTLS13RecordError.unsupportedContentType(firstByte)
          }
          var headerCursor = offset + 1
          let hasConnectionID = firstByte & 0x10 != 0
          guard hasConnectionID == (expectedConnectionIDByteCount > 0) else {
            throw DTLS13RecordError.connectionIDMismatch
          }
          if hasConnectionID {
            headerCursor += expectedConnectionIDByteCount
          }
          headerCursor += firstByte & 0x08 == 0 ? 1 : 2
          guard headerCursor <= datagram.count else {
            throw DTLS13RecordError.malformedRecord
          }
          if firstByte & 0x04 != 0 {
            guard headerCursor + 2 <= datagram.count else {
              throw DTLS13RecordError.malformedRecord
            }
            let ciphertextByteCount =
              (Int(datagram[headerCursor]) << 8)
              | Int(datagram[headerCursor + 1])
            headerCursor += 2
            let headerByteCount = headerCursor - offset
            let (total, overflow) = headerByteCount.addingReportingOverflow(
              ciphertextByteCount
            )
            guard !overflow, total <= datagram.count - offset else {
              throw DTLS13RecordError.malformedRecord
            }
            recordByteCount = total
          } else {
            recordByteCount = datagram.count - offset
          }
          kind = .ciphertext(epochBits: firstByte & 0x03)
        }
        records.append(
          DTLS13DatagramRecord(
            kind: kind,
            bytes: try ByteRange(offset: offset, count: recordByteCount)
          )
        )
        offset += recordByteCount
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
}
