import SSLCore
import SSLDTLS
import XCTest

final class DTLS12Tests: XCTestCase {
  func testExtensionsRoundTrip() throws {
    let extensions = try DTLS12SecurityExtensions(
      protectionProfiles: [.aes128CMHMACSHA180],
      mki: [1, 2, 3]
    )
    let encoded = try extensions.encode()
    let decoded = try encoded.withBorrowedBytes { bytes in
      try DTLS12SecurityExtensions.decode(bytes)
    }
    XCTAssertEqual(decoded, extensions)
  }

  func testAEADRoundTripAndTamperRejection() throws {
    let key = ContiguousArray(repeating: UInt8(0x11), count: 16)
    let iv = ContiguousArray(repeating: UInt8(0x22), count: 4)
    let protector = try DTLS12AESGCMRecordProtector(
      key: key.span,
      fixedIV: iv.span,
      epoch: 1
    )
    let message = ContiguousArray("hello DTLS".utf8)
    let sealed = try message.withUnsafeBufferPointer { messageBuffer in
      return try protector.seal(
        plaintext: Span(_unsafeElements: messageBuffer),
        contentType: 23,
        sequenceNumber: 7
      )
    }
    let opened = try sealed.withBorrowedBytes { record in
      try protector.open(recordFragment: record, contentType: 23)
    }
    let expected = message.withUnsafeBufferPointer { buffer in
      OwnedBytes(copying: Span(_unsafeElements: buffer))
    }
    XCTAssertEqual(opened, expected)

    var tampered = ContiguousArray<UInt8>(repeating: 0, count: sealed.count)
    sealed.withBorrowedBytes { bytes in
      var index = 0
      while index < bytes.count { tampered[index] = bytes[index]; index += 1 }
    }
    tampered[tampered.count - 1] ^= 1
    XCTAssertThrowsError(
      try tampered.withUnsafeBufferPointer { buffer in
        try protector.open(recordFragment: Span(_unsafeElements: buffer), contentType: 23)
      }
    ) { error in
      XCTAssertTrue(error is DTLS12RecordError)
    }
  }
}
