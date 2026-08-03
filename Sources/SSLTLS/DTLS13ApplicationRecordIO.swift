import SSLCore

enum DTLS13ApplicationRecordIO {
  static func seal(
    _ content: Span<UInt8>,
    using protector: inout RFC9147DTLS13RecordProtector
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    try seal(
      content,
      contentType: .applicationData,
      using: &protector
    )
  }

  static func makeAcknowledgment(
    recordNumbers: consuming ContiguousArray<DTLS13RecordNumber>,
    using protector: inout RFC9147DTLS13RecordProtector
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let acknowledgment: DTLS13Acknowledgment
    let encoded: OwnedBytes
    do {
      acknowledgment = try DTLS13Acknowledgment(
        recordNumbers: recordNumbers
      )
      encoded = try RFC9147DTLS13AcknowledgmentCodec().encode(
        acknowledgment
      )
    } catch let error {
      throw .acknowledgment(error)
    }
    return try seal(
      encoded.span,
      contentType: .acknowledgment,
      using: &protector
    )
  }

  private static func seal(
    _ content: Span<UInt8>,
    contentType: DTLS13RecordContentType,
    using protector: inout RFC9147DTLS13RecordProtector
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let recordByteCount: Int
    do {
      recordByteCount = try protector.sealedRecordByteCount(
        contentByteCount: content.count
      )
    } catch let error {
      throw .record(error)
    }
    var record = ContiguousArray<UInt8>(repeating: 0, count: recordByteCount)
    do {
      _ = try record.withUnsafeMutableBufferPointer { buffer in
        // The allocation is uniquely borrowed for the synchronous seal and the
        // pointer cannot escape. The protector validated the exact initialized
        // byte count, and UInt8 requires no rebinding or alignment adjustment.
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: buffer.count
        )
        return try protector.seal(
          content: content,
          contentType: contentType,
          into: &destination
        )
      }
      let bytes = OwnedBytes(consuming: record)
      let range = try ByteRange(offset: 0, count: bytes.count)
      return try DTLSActionBatch(
        bytes: bytes,
        actions: [.emitDatagram(range), .flushFlight]
      )
    } catch let error as DTLS13RecordError {
      throw .record(error)
    } catch let error as ByteError {
      throw .output(error)
    } catch {
      throw .invalidState
    }
  }

  static func deliver(
    _ content: consuming OwnedBytes
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    do {
      let range = try ByteRange(offset: 0, count: content.count)
      return try DTLSActionBatch(
        bytes: content,
        actions: [
          .deliverApplicationData(bytes: range, isEarlyData: false)
        ]
      )
    } catch let error {
      throw .output(error)
    }
  }
}
