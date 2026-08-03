import SSLCore
import SSLCrypto
import SSLTLS
import XCTest

final class DTLS13RecordProtectorTests: XCTestCase {
  func testRoundTripsEverySupportedCipherSuiteWithRecordNumberProtection() throws {
    for suite in TLSCipherSuite.allCases {
      let secretByteCount = suite == .aes256GCM_SHA384 ? 48 : 32
      let secret = ContiguousArray<UInt8>(repeating: 0xA5, count: secretByteCount)
      let connectionID: ContiguousArray<UInt8> = [9, 8, 7]
      var sender = try RFC9147DTLS13RecordProtector(
        cipherSuite: suite,
        trafficSecret: secret.span,
        epoch: 2,
        connectionID: connectionID.span
      )
      var receiver = try RFC9147DTLS13RecordProtector(
        cipherSuite: suite,
        trafficSecret: secret.span,
        epoch: 2,
        connectionID: connectionID.span
      )
      let plaintext: ContiguousArray<UInt8> = [1, 2, 3, 4]
      let recordByteCount = try sender.sealedRecordByteCount(
        contentByteCount: plaintext.count
      )
      var record = ContiguousArray<UInt8>(repeating: 0, count: recordByteCount)
      let sentRecordNumber = try record.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: buffer.count
        )
        return try sender.seal(
          content: plaintext.span,
          contentType: .handshake,
          into: &destination
        )
      }
      XCTAssertEqual(sentRecordNumber.sequenceNumber, 0)
      XCTAssertNotEqual(record[1 + connectionID.count], 0)

      var opened = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count)
      let contentType = try opened.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: buffer.count
        )
        return try receiver.open(record: record.span, into: &destination)
      }
      XCTAssertEqual(contentType, .handshake)
      XCTAssertEqual(opened, plaintext)
      XCTAssertEqual(receiver.lastOpenedRecordNumber, sentRecordNumber)
    }
  }

  func testRejectsAuthenticatedRecordReplay() throws {
    let secret = ContiguousArray<UInt8>(repeating: 0x5A, count: 32)
    var sender = try RFC9147DTLS13RecordProtector(
      cipherSuite: .aes128GCM_SHA256,
      trafficSecret: secret.span,
      epoch: 2
    )
    var receiver = try RFC9147DTLS13RecordProtector(
      cipherSuite: .aes128GCM_SHA256,
      trafficSecret: secret.span,
      epoch: 2
    )
    let plaintext: ContiguousArray<UInt8> = [1]
    var record = ContiguousArray<UInt8>(
      repeating: 0,
      count: try sender.sealedRecordByteCount(contentByteCount: 1)
    )
    _ = try record.withUnsafeMutableBufferPointer { buffer in
      var destination = MutableSpan(
        _unsafeStart: buffer.baseAddress!,
        count: buffer.count
      )
      return try sender.seal(
        content: plaintext.span,
        contentType: .handshake,
        into: &destination
      )
    }
    var opened = ContiguousArray<UInt8>(repeating: 0, count: 1)
    _ = try opened.withUnsafeMutableBufferPointer { buffer in
      var destination = MutableSpan(
        _unsafeStart: buffer.baseAddress!,
        count: buffer.count
      )
      return try receiver.open(record: record.span, into: &destination)
    }
    let replayedRecordNumber = try DTLS13RecordNumber(
      epoch: 2,
      sequenceNumber: 0
    )
    XCTAssertThrowsError(
      try opened.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: buffer.count
        )
        _ = try receiver.open(record: record.span, into: &destination)
      }
    ) { error in
      XCTAssertEqual(
        error as? DTLS13RecordError,
        .replayed(replayedRecordNumber)
      )
    }
  }

  func testRejectsCiphertextTamperingWithoutAdvancingReplayWindow() throws {
    let secret = ContiguousArray<UInt8>(repeating: 0x3C, count: 32)
    var sender = try RFC9147DTLS13RecordProtector(
      cipherSuite: .chacha20Poly1305_SHA256,
      trafficSecret: secret.span,
      epoch: 3
    )
    var receiver = try RFC9147DTLS13RecordProtector(
      cipherSuite: .chacha20Poly1305_SHA256,
      trafficSecret: secret.span,
      epoch: 3
    )
    let plaintext: ContiguousArray<UInt8> = [4, 5, 6]
    var record = ContiguousArray<UInt8>(
      repeating: 0,
      count: try sender.sealedRecordByteCount(contentByteCount: plaintext.count)
    )
    _ = try record.withUnsafeMutableBufferPointer { buffer in
      var destination = MutableSpan(
        _unsafeStart: buffer.baseAddress!,
        count: buffer.count
      )
      return try sender.seal(
        content: plaintext.span,
        contentType: .applicationData,
        into: &destination
      )
    }
    var tampered = record
    tampered[tampered.count - 1] ^= 1
    var opened = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count)
    XCTAssertThrowsError(
      try opened.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: buffer.count
        )
        _ = try receiver.open(record: tampered.span, into: &destination)
      }
    )
    let contentType = try opened.withUnsafeMutableBufferPointer { buffer in
      var destination = MutableSpan(
        _unsafeStart: buffer.baseAddress!,
        count: buffer.count
      )
      return try receiver.open(record: record.span, into: &destination)
    }
    XCTAssertEqual(contentType, .applicationData)
    XCTAssertEqual(opened, plaintext)
  }

  func testReconstructsSequenceNumberNearestExpectedValue() throws {
    let reconstructor = RFC9147DTLS13SequenceNumberReconstructor()
    XCTAssertEqual(
      try reconstructor.reconstruct(
        truncatedSequenceNumber: 0,
        bitCount: 8,
        highestAuthenticatedSequenceNumber: 255
      ),
      256
    )
    XCTAssertEqual(
      try reconstructor.reconstruct(
        truncatedSequenceNumber: 255,
        bitCount: 8,
        highestAuthenticatedSequenceNumber: 256
      ),
      255
    )
  }
}
