import XCTest

@testable import SSLCrypto

final class LegacyDigestTests: XCTestCase {
  func testSHA1KnownAnswers() throws {
    try assertDigest(
      SHA1Context(),
      input: [],
      expected: "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
    try assertDigest(
      SHA1Context(),
      input: [0x61, 0x62, 0x63],
      expected: "a9993e364706816aba3e25717850c26c9cd0d89d"
    )
  }

  func testMD5KnownAnswers() throws {
    try assertDigest(
      MD5Context(),
      input: [],
      expected: "d41d8cd98f00b204e9800998ecf8427e"
    )
    try assertDigest(
      MD5Context(),
      input: [0x61, 0x62, 0x63],
      expected: "900150983cd24fb0d6963f7d28e17f72"
    )
  }

  private func assertDigest<Context: HashContext & ~Copyable>(
    _ context: consuming Context,
    input: [UInt8],
    expected: String
  ) throws {
    var context = context
    try input.withUnsafeBufferPointer { buffer in
      let span = Span(_unsafeElements: buffer)
      try context.update(span)
    }
    var output = ContiguousArray<UInt8>(repeating: 0, count: Context.digestByteCount)
    var outputSpan = output.mutableSpan
    try context.finalize(into: &outputSpan)
    XCTAssertEqual(hex(output), expected)
  }

  private func hex(_ bytes: ContiguousArray<UInt8>) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }
}
