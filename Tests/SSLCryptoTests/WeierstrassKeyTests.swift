import SSLCore
import XCTest

@testable import SSLCrypto

final class WeierstrassKeyTests: XCTestCase {
  func testP384KeyAgreementAndCompressedRoundTrip() throws {
    let one = try P384PrivateKey(bytes: scalar(count: P384PrivateKey.byteCount, value: 1).span)
    let two = try P384PrivateKey(bytes: scalar(count: P384PrivateKey.byteCount, value: 2).span)
    let onePublic = one.publicKey()
    let twoPublic = two.publicKey()
    XCTAssertEqual(
      copySpan(onePublic.span),
      Array(bytes("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7" + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"))
    )
    XCTAssertEqual(
      copySpan(twoPublic.span),
      Array(bytes("0408D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF618E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80"))
    )
    let compressed = twoPublic.compressedBytes()
    let decoded = try P384PublicKey(compressedBytes: compressed.span)
    XCTAssertEqual(copySpan(decoded.span), copySpan(twoPublic.span))
    let first = try P384KeyAgreement.sharedSecret(privateKey: one, peerPublicKey: twoPublic)
    let second = try P384KeyAgreement.sharedSecret(privateKey: two, peerPublicKey: onePublic)
    XCTAssertEqual(copy(first), copy(second))
  }

  func testP521KeyAgreementAndCompressedRoundTrip() throws {
    let one = try P521PrivateKey(bytes: scalar(count: P521PrivateKey.byteCount, value: 1).span)
    let two = try P521PrivateKey(bytes: scalar(count: P521PrivateKey.byteCount, value: 2).span)
    let onePublic = one.publicKey()
    let twoPublic = two.publicKey()
    XCTAssertEqual(
      copySpan(onePublic.span),
      Array(bytes("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66" + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"))
    )
    XCTAssertEqual(
      copySpan(twoPublic.span),
      Array(bytes("0400433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02"))
    )
    let compressed = twoPublic.compressedBytes()
    let decoded = try P521PublicKey(compressedBytes: compressed.span)
    XCTAssertEqual(copySpan(decoded.span), copySpan(twoPublic.span))
    let first = try P521KeyAgreement.sharedSecret(privateKey: one, peerPublicKey: twoPublic)
    let second = try P521KeyAgreement.sharedSecret(privateKey: two, peerPublicKey: onePublic)
    XCTAssertEqual(copy(first), copy(second))
  }

  func testP384AndP521SigningRoundTrip() throws {
    let p384 = try P384PrivateKey(bytes: scalar(count: P384PrivateKey.byteCount, value: 1).span)
    let p384Digest = bytes("CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7")
    let p384Signature = try P384ECDSA.sign(messageHash: p384Digest.span, using: p384)
    XCTAssertTrue(try P384ECDSA.verify(signature: p384Signature.span, messageHash: p384Digest.span, using: p384.publicKey()))

    let p521 = try P521PrivateKey(bytes: scalar(count: P521PrivateKey.byteCount, value: 1).span)
    let p521Digest = bytes("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F")
    let p521Signature = try P521ECDSA.sign(messageHash: p521Digest.span, using: p521)
    XCTAssertTrue(try P521ECDSA.verify(signature: p521Signature.span, messageHash: p521Digest.span, using: p521.publicKey()))
  }

  private func scalar(count: Int, value: UInt8) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>(repeating: 0, count: count)
    result[count - 1] = value
    return result
  }

  private func copySpan(_ span: Span<UInt8>) -> [UInt8] {
    var result = [UInt8]()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private func copy(_ secret: borrowing P384SharedSecret) -> [UInt8] {
    secret.withBorrowedBytes { bytes in
      var result = [UInt8](); result.reserveCapacity(bytes.count)
      var index = 0; while index < bytes.count { result.append(bytes[index]); index += 1 }
      return result
    }
  }

  private func copy(_ secret: borrowing P521SharedSecret) -> [UInt8] {
    secret.withBorrowedBytes { bytes in
      var result = [UInt8](); result.reserveCapacity(bytes.count)
      var index = 0; while index < bytes.count { result.append(bytes[index]); index += 1 }
      return result
    }
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
