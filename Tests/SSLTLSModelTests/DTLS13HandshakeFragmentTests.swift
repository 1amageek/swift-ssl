import SSLCore
import SSLTLS
import XCTest

final class DTLS13HandshakeFragmentTests: XCTestCase {
  func testReassemblesOutOfOrderFragmentsIntoTLSHandshakeMessage() throws {
    let codec = try RFC9147DTLS13HandshakeFragmentCodec()
    let message: ContiguousArray<UInt8> = [1, 0, 0, 6, 10, 11, 12, 13, 14, 15]
    var second = ContiguousArray<UInt8>()
    var first = ContiguousArray<UInt8>()
    try codec.appendFragment(
      tlsHandshakeMessage: message.span,
      messageSequence: 0,
      fragmentOffset: 3,
      fragmentByteCount: 3,
      to: &second
    )
    try codec.appendFragment(
      tlsHandshakeMessage: message.span,
      messageSequence: 0,
      fragmentOffset: 0,
      fragmentByteCount: 3,
      to: &first
    )

    var reassembler = try RFC9147DTLS13HandshakeReassembler()
    let secondFragment = try XCTUnwrap(codec.fragments(in: second.span).first)
    try reassembler.receive(secondFragment, from: second.span)
    XCTAssertNil(reassembler.takeNextMessage())
    let firstFragment = try XCTUnwrap(codec.fragments(in: first.span).first)
    try reassembler.receive(firstFragment, from: first.span)
    let complete = try XCTUnwrap(reassembler.takeNextMessage())
    XCTAssertEqual(complete, OwnedBytes(copying: message.span))
    XCTAssertEqual(reassembler.nextReceiveSequence, 1)
    XCTAssertEqual(reassembler.bufferedByteCount, 0)
  }

  func testRejectsConflictingOverlap() throws {
    let codec = try RFC9147DTLS13HandshakeFragmentCodec()
    let original: ContiguousArray<UInt8> = [1, 0, 0, 3, 1, 2, 3]
    let changed: ContiguousArray<UInt8> = [1, 0, 0, 3, 1, 9, 3]
    var first = ContiguousArray<UInt8>()
    var overlap = ContiguousArray<UInt8>()
    try codec.appendFragment(
      tlsHandshakeMessage: original.span,
      messageSequence: 0,
      fragmentOffset: 0,
      fragmentByteCount: 2,
      to: &first
    )
    try codec.appendFragment(
      tlsHandshakeMessage: changed.span,
      messageSequence: 0,
      fragmentOffset: 1,
      fragmentByteCount: 2,
      to: &overlap
    )

    var reassembler = try RFC9147DTLS13HandshakeReassembler()
    try reassembler.receive(
      try XCTUnwrap(codec.fragments(in: first.span).first),
      from: first.span
    )
    XCTAssertThrowsError(
      try reassembler.receive(
        try XCTUnwrap(codec.fragments(in: overlap.span).first),
        from: overlap.span
      )
    ) { error in
      XCTAssertEqual(
        error as? DTLS13HandshakeFragmentError,
        .conflictingOverlap(sequence: 0, offset: 1)
      )
    }
  }
}
