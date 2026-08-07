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

  func testRawAEADWritesIntoCallerOwnedBuffers() throws {
    let key = ContiguousArray(repeating: UInt8(0x31), count: 16)
    let iv = ContiguousArray(repeating: UInt8(0x42), count: 4)
    let protector = try DTLS12AESGCMRecordProtector(
      key: key.span,
      fixedIV: iv.span,
      epoch: 1
    )
    let message = ContiguousArray("borrowed DTLS record".utf8)
    let explicitNonce = ContiguousArray<UInt8>([0, 1, 0, 0, 0, 0, 0, 7])
    let authenticatedData = ContiguousArray(repeating: UInt8(0xA5), count: 13)
    var sealed = ContiguousArray<UInt8>(
      repeating: 0,
      count: explicitNonce.count + message.count + DTLS12AESGCMRecordProtector.tagByteCount
    )
    try sealed.withUnsafeMutableBufferPointer { sealedBuffer in
      var sealedSpan = MutableSpan(_unsafeElements: sealedBuffer)
      try protector.sealRaw(
        plaintext: message.span,
        explicitNonce: explicitNonce.span,
        authenticatedData: authenticatedData.span,
        into: &sealedSpan
      )
    }

    var opened = ContiguousArray<UInt8>(repeating: 0, count: message.count)
    try opened.withUnsafeMutableBufferPointer { openedBuffer in
      var openedSpan = MutableSpan(_unsafeElements: openedBuffer)
      try protector.openRaw(
        recordFragment: sealed.span,
        authenticatedData: authenticatedData.span,
        into: &openedSpan
      )
    }
    XCTAssertEqual(opened, message)
  }

  func testRawAEADRejectsWrongOutputSizeAndTamperBeforePlaintextWrite() throws {
    let key = ContiguousArray(repeating: UInt8(0x51), count: 16)
    let iv = ContiguousArray(repeating: UInt8(0x62), count: 4)
    let protector = try DTLS12AESGCMRecordProtector(
      key: key.span,
      fixedIV: iv.span,
      epoch: 1
    )
    let message = ContiguousArray("authenticated before output".utf8)
    let explicitNonce = ContiguousArray<UInt8>([0, 1, 0, 0, 0, 0, 0, 9])
    let authenticatedData = ContiguousArray(repeating: UInt8(0xB6), count: 13)
    var sealed = ContiguousArray<UInt8>(
      repeating: 0,
      count: explicitNonce.count + message.count + DTLS12AESGCMRecordProtector.tagByteCount
    )
    try sealed.withUnsafeMutableBufferPointer { sealedBuffer in
      var sealedSpan = MutableSpan(_unsafeElements: sealedBuffer)
      try protector.sealRaw(
        plaintext: message.span,
        explicitNonce: explicitNonce.span,
        authenticatedData: authenticatedData.span,
        into: &sealedSpan
      )
    }

    var tooSmall = ContiguousArray<UInt8>(repeating: 0, count: message.count - 1)
    XCTAssertThrowsError(
      try tooSmall.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try protector.openRaw(
          recordFragment: sealed.span,
          authenticatedData: authenticatedData.span,
          into: &output
        )
      }
    ) { error in
      XCTAssertEqual(
        error as? DTLS12RecordError,
        .aead(.outputTooSmall(required: message.count, actual: message.count - 1))
      )
    }

    sealed[sealed.count - 1] ^= 1
    var untouched = ContiguousArray<UInt8>(repeating: 0xCD, count: message.count)
    XCTAssertThrowsError(
      try untouched.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try protector.openRaw(
          recordFragment: sealed.span,
          authenticatedData: authenticatedData.span,
          into: &output
        )
      }
    ) { error in
      XCTAssertEqual(error as? DTLS12RecordError, .aead(.authenticationFailed))
    }
    XCTAssertEqual(untouched, ContiguousArray(repeating: 0xCD, count: message.count))
  }
}
