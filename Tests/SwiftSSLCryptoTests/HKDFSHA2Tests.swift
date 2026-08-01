import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class HKDFSHA2Tests: XCTestCase {
  func testRFC5869ShapeForSHA384AndSHA512() throws {
    let input = ContiguousArray<UInt8>(repeating: 0x0B, count: 22)
    let salt = ContiguousArray<UInt8>(0...12)
    let info = ContiguousArray<UInt8>([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9])
    let expectedPRK384 = bytes(
      "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade"
    )
    let expectedOKM384 = bytes(
      "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5")
    let expectedPRK512 = bytes(
      "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237"
    )
    let expectedOKM512 = bytes(
      "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137"
    )

    var prk384 = ContiguousArray<UInt8>(repeating: 0, count: HKDFSHA384.pseudorandomKeyByteCount)
    var prk384Span = prk384.mutableSpan
    try HKDFSHA384.extract(inputKeyMaterial: input.span, salt: salt.span, into: &prk384Span)
    XCTAssertEqual(prk384, expectedPRK384)
    var okm384 = ContiguousArray<UInt8>(repeating: 0, count: expectedOKM384.count)
    var okm384Span = okm384.mutableSpan
    try HKDFSHA384.expand(pseudorandomKey: prk384.span, info: info.span, into: &okm384Span)
    XCTAssertEqual(okm384, expectedOKM384)

    var prk512 = ContiguousArray<UInt8>(repeating: 0, count: HKDFSHA512.pseudorandomKeyByteCount)
    var prk512Span = prk512.mutableSpan
    try HKDFSHA512.extract(inputKeyMaterial: input.span, salt: salt.span, into: &prk512Span)
    XCTAssertEqual(prk512, expectedPRK512)
    var okm512 = ContiguousArray<UInt8>(repeating: 0, count: expectedOKM512.count)
    var okm512Span = okm512.mutableSpan
    try HKDFSHA512.expand(pseudorandomKey: prk512.span, info: info.span, into: &okm512Span)
    XCTAssertEqual(okm512, expectedOKM512)
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }
}
