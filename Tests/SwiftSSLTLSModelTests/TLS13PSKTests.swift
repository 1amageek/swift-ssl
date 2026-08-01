import SwiftSSLCore
import SwiftSSLCrypto
import XCTest

@testable import SwiftSSLTLS

final class TLS13PSKTests: XCTestCase {
  func testPreSharedKeyExtensionRoundTrip() throws {
    let identity = try TLS13PSKIdentity(
      identity: ContiguousArray<UInt8>([0xA0, 0xB0]).span,
      obfuscatedTicketAge: 123
    )
    let binder = try TLS13PSKBinder(
      value: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span
    )
    let extensionValue = try TLS13PreSharedKeyExtension(
      identities: ContiguousArray([identity]),
      binders: ContiguousArray([binder])
    )
    let encoded = try extensionValue.encodedValue()
    let parsed = try TLS13PreSharedKeyExtension.parse(encoded.span)
    XCTAssertEqual(parsed.identities.count, 1)
    XCTAssertEqual(parsed.binders.count, 1)
    let parsedIdentity = parsed.identities[0]
    let parsedBinder = parsed.binders[0]
    XCTAssertEqual(parsedIdentity.obfuscatedTicketAge, 123)
    XCTAssertEqual(copy(parsedIdentity.identity.span), [0xA0, 0xB0])
    XCTAssertEqual(copy(parsedBinder.value.span), Array(repeating: 0x11, count: 32))
  }

  func testClientHelloCarriesPreSharedKeyAsLastExtension() throws {
    let identity = try TLS13PSKIdentity(
      identity: ContiguousArray<UInt8>([1, 2, 3]).span,
      obfuscatedTicketAge: 7
    )
    let binder = try TLS13PSKBinder(
      value: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
    )
    let psk = try TLS13PreSharedKeyExtension(
      identities: ContiguousArray([identity]),
      binders: ContiguousArray([binder])
    )
    let hello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x33, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x44, count: 32).span,
      preSharedKey: psk
    )
    let parsed = try TLS13HandshakeCodec.parseClientHello(hello.span)
    XCTAssertEqual(parsed.preSharedKey, psk)
  }

  func testPreSharedKeyExtensionRejectsDuplicateIdentities() throws {
    let identity = try TLS13PSKIdentity(
      identity: ContiguousArray<UInt8>([0xAA]).span,
      obfuscatedTicketAge: 0
    )
    let firstBinder = try TLS13PSKBinder(
      value: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span
    )
    let secondBinder = try TLS13PSKBinder(
      value: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
    )
    do {
      _ = try TLS13PreSharedKeyExtension(
        identities: ContiguousArray([identity, identity]),
        binders: ContiguousArray([firstBinder, secondBinder])
      )
      XCTFail("duplicate PSK identities were accepted")
    } catch {
      XCTAssertEqual(error, .duplicateIdentity)
    }
  }

  func testBinderVerificationIsConstantTimeAndSuiteSized() throws {
    let psk = try SecretBytes(
      copying: ContiguousArray<UInt8>(repeating: 0x55, count: 32).span
    )
    let transcriptHash = ContiguousArray<UInt8>(repeating: 0x66, count: 32)
    let binder = try TLS13PSKBinder.compute(
      preSharedKey: psk,
      cipherSuite: .aes128GCM_SHA256,
      transcriptHash: transcriptHash.span
    )
    XCTAssertTrue(
      try TLS13PSKBinder.verify(
        preSharedKey: psk,
        cipherSuite: .aes128GCM_SHA256,
        transcriptHash: transcriptHash.span,
        binder: binder.span
      )
    )
    var modified = ContiguousArray(copy(binder.span))
    modified[0] ^= 1
    XCTAssertFalse(
      try TLS13PSKBinder.verify(
        preSharedKey: psk,
        cipherSuite: .aes128GCM_SHA256,
        transcriptHash: transcriptHash.span,
        binder: modified.span
      )
    )
  }

  func testRFC8448ResumptionBinderKnownAnswer() throws {
    let preSharedKeyBytes = try bytes(
      fromHex: "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"
    )
    let preSharedKey = try SecretBytes(copying: preSharedKeyBytes.span)
    let transcriptHash = try bytes(
      fromHex: "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"
    )
    let expected = try bytes(
      fromHex: "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"
    )

    let actual = try TLS13PSKBinder.compute(
      preSharedKey: preSharedKey,
      cipherSuite: .aes128GCM_SHA256,
      transcriptHash: transcriptHash.span
    )

    XCTAssertEqual(copy(actual.span), copy(expected.span))
  }

  func testRFC8448ClientHelloBinderTruncationKnownAnswer() throws {
    let clientHello = try bytes(
      fromHex: """
        010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95
        000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012
        001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99d
        a26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e
        040305030603020308040805080604010501060102010402050206020202002d00020101001c00
        024001001500570000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec90000
        0000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097
        a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d
        4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda4
        0dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e9
        3343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5
        924d57bb6fa31b9e5f9d
        """
    )
    XCTAssertEqual(clientHello.count, 512)

    let truncated = try TLS13HandshakeCodec.truncatedClientHelloForBinder(
      clientHello.span
    )
    XCTAssertEqual(truncated.count, 477)

    var digest = ContiguousArray<UInt8>(
      repeating: 0,
      count: SHA256.digestByteCount
    )
    var destination = digest.mutableSpan
    try SHA256.hash(truncated.span, into: &destination)
    let expected = try bytes(
      fromHex: "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"
    )
    XCTAssertEqual(digest, expected)
  }

  func testRFC8448ResumptionPSKKnownAnswer() throws {
    let masterBytes = try bytes(
      fromHex: "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"
    )
    let master = try SecretBytes(copying: masterBytes.span)
    let nonce = try bytes(fromHex: "0000")
    let expected = try bytes(
      fromHex: "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"
    )

    let actual = try TLS13KeySchedule.deriveResumptionPSK(
      resumptionMasterSecret: master,
      ticketNonce: nonce.span,
      cipherSuite: .aes128GCM_SHA256
    )

    try actual.withBorrowedBytes { value in
      XCTAssertEqual(copy(value), copy(expected.span))
    }
  }

  private func copy(_ span: Span<UInt8>) -> [UInt8] {
    var result = [UInt8]()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private func bytes(
    fromHex string: String
  ) throws -> ContiguousArray<UInt8> {
    var highNibble: UInt8?
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(string.utf8.count / 2)
    for byte in string.utf8 {
      if byte == 0x20 || byte == 0x0A || byte == 0x0D || byte == 0x09 {
        continue
      }
      guard let nibble = hexadecimalValue(byte) else {
        throw FixtureError.invalidHex
      }
      if let high = highNibble {
        result.append((high << 4) | nibble)
        highNibble = nil
      } else {
        highNibble = nibble
      }
    }
    guard highNibble == nil else { throw FixtureError.invalidHex }
    return result
  }

  private func hexadecimalValue(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39:
      byte - 0x30
    case 0x61...0x66:
      byte - 0x61 + 10
    case 0x41...0x46:
      byte - 0x41 + 10
    default:
      nil
    }
  }

  private enum FixtureError: Error {
    case invalidHex
  }
}
