import SSLCore
import SSLCrypto
import XCTest

@testable import SSLTLS

final class DTLS13CookieTests: XCTestCase {
  func testAuthenticatedCookieBindsPeerAndExpires() throws {
    let key = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
    let clientHelloHash = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: 32
    )
    let peerIdentity: ContiguousArray<UInt8> = [
      0x7F, 0x00, 0x00, 0x01, 0x20, 0xFB,
    ]
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let protector = try HMACSHA256DTLS13CookieProtector(
      key: key.span,
      maximumAgeSeconds: 30
    )
    let cookie = try protector.issueCookie(
      clientHelloHash: clientHelloHash.span,
      cipherSuite: .aes128GCM_SHA256,
      peerIdentity: peerIdentity.span,
      at: issuedAt
    )
    let validAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_029,
      nanoseconds: 999_999_999
    )
    let validated = try protector.validateCookie(
      cookie.span,
      peerIdentity: peerIdentity.span,
      at: validAt
    )
    XCTAssertEqual(validated.clientHelloHash, OwnedBytes(copying: clientHelloHash.span))
    XCTAssertEqual(validated.cipherSuite.rawValue, TLSCipherSuite.aes128GCM_SHA256.rawValue)
    XCTAssertEqual(validated.issuedAt, issuedAt)

    let differentPeer: ContiguousArray<UInt8> = [
      0x7F, 0x00, 0x00, 0x02, 0x20, 0xFB,
    ]
    XCTAssertThrowsError(
      try protector.validateCookie(
        cookie.span,
        peerIdentity: differentPeer.span,
        at: validAt
      )
    ) { error in
      XCTAssertEqual(error as? DTLS13CookieError, .authenticationFailed)
    }
    let expiredAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_031,
      nanoseconds: 0
    )
    XCTAssertThrowsError(
      try protector.validateCookie(
        cookie.span,
        peerIdentity: peerIdentity.span,
        at: expiredAt
      )
    ) { error in
      XCTAssertEqual(error as? DTLS13CookieError, .expired)
    }
  }

  func testDTLSClientHelloAndHelloRetryRequestCarryCookieExtension() throws {
    let cookie: ContiguousArray<UInt8> = [0x10, 0x20, 0x30, 0x40]
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
      cookie: cookie.span,
      encoding: .dtls13
    )
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span,
      encoding: .dtls13
    )
    XCTAssertEqual(parsedClientHello.cookie, OwnedBytes(copying: cookie.span))

    let helloRetryRequest = try TLS13HandshakeCodec.makeHelloRetryRequest(
      cookie: cookie.span,
      cipherSuite: .aes128GCM_SHA256,
      encoding: .dtls13
    )
    let parsedRetry = try TLS13HandshakeCodec.parseHelloRetryRequest(
      helloRetryRequest.span,
      encoding: .dtls13
    )
    XCTAssertEqual(parsedRetry.cookie, OwnedBytes(copying: cookie.span))
    XCTAssertEqual(
      parsedRetry.cipherSuite.rawValue,
      TLSCipherSuite.aes128GCM_SHA256.rawValue
    )
    XCTAssertNil(parsedRetry.echAcceptanceConfirmation)
  }
}
