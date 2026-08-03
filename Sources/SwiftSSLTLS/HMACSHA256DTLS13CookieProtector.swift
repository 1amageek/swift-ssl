import SwiftSSLCore
import SwiftSSLCrypto

public final class HMACSHA256DTLS13CookieProtector:
  DTLS13CookieProtecting,
  Sendable
{
  private static let formatVersion: UInt8 = 1
  private static let headerByteCount = 1 + 8 + 2
  private static let domain: ContiguousArray<UInt8> = [
    0x73, 0x77, 0x69, 0x66, 0x74, 0x2D, 0x73, 0x73,
    0x6C, 0x20, 0x44, 0x54, 0x4C, 0x53, 0x20, 0x63,
    0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x20, 0x76, 0x31,
  ]

  private let key: SecretBytes
  public let maximumAgeSeconds: Int64

  public init(
    key: Span<UInt8>,
    maximumAgeSeconds: Int64 = 60
  ) throws(DTLS13CookieError) {
    guard key.count >= 32, maximumAgeSeconds > 0 else {
      throw .invalidConfiguration
    }
    do {
      self.key = try SecretBytes(copying: key)
    } catch {
      throw .invalidConfiguration
    }
    self.maximumAgeSeconds = maximumAgeSeconds
  }

  public borrowing func issueCookie(
    clientHelloHash: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    peerIdentity: Span<UInt8>,
    at instant: VerificationInstant
  ) throws(DTLS13CookieError) -> OwnedBytes {
    let hashByteCount = TLS13RecordProtector.hashByteCount(for: cipherSuite)
    guard clientHelloHash.count == hashByteCount,
      !peerIdentity.isEmpty,
      peerIdentity.count <= UInt16.max
    else {
      throw .invalidConfiguration
    }
    var cookie = ContiguousArray<UInt8>()
    cookie.reserveCapacity(
      Self.headerByteCount + hashByteCount + HMACSHA256.tagByteCount
    )
    cookie.append(Self.formatVersion)
    Self.appendUInt64(
      UInt64(bitPattern: instant.secondsSinceUnixEpoch),
      to: &cookie
    )
    cookie.append(UInt8(truncatingIfNeeded: cipherSuite.rawValue >> 8))
    cookie.append(UInt8(truncatingIfNeeded: cipherSuite.rawValue))
    Self.append(clientHelloHash, to: &cookie)
    let payloadByteCount = cookie.count
    let tag = try authenticationCode(
      payload: cookie.span,
      peerIdentity: peerIdentity
    )
    Self.append(tag.span, to: &cookie)
    guard cookie.count == payloadByteCount + HMACSHA256.tagByteCount else {
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: cookie)
  }

  public borrowing func validateCookie(
    _ cookie: Span<UInt8>,
    peerIdentity: Span<UInt8>,
    at instant: VerificationInstant
  ) throws(DTLS13CookieError) -> DTLS13CookieValidation {
    guard !peerIdentity.isEmpty,
      peerIdentity.count <= UInt16.max,
      cookie.count >= Self.headerByteCount + 32 + HMACSHA256.tagByteCount,
      cookie[0] == Self.formatVersion
    else {
      throw .malformedCookie
    }
    let suiteOffset = 9
    let rawSuite = UInt16(cookie[suiteOffset]) << 8
      | UInt16(cookie[suiteOffset + 1])
    guard let cipherSuite = TLSCipherSuite(rawValue: rawSuite) else {
      throw .malformedCookie
    }
    let hashByteCount = TLS13RecordProtector.hashByteCount(for: cipherSuite)
    let payloadByteCount = Self.headerByteCount + hashByteCount
    guard cookie.count == payloadByteCount + HMACSHA256.tagByteCount else {
      throw .malformedCookie
    }
    let payload = cookie.extracting(0..<payloadByteCount)
    let tag = cookie.extracting(payloadByteCount..<cookie.count)
    guard try isValidAuthenticationCode(
      tag,
      payload: payload,
      peerIdentity: peerIdentity
    ) else {
      throw .authenticationFailed
    }
    let issuedSeconds = Int64(
      bitPattern: Self.readUInt64(cookie.extracting(1..<9))
    )
    let (age, overflow) = instant.secondsSinceUnixEpoch
      .subtractingReportingOverflow(issuedSeconds)
    guard !overflow, age >= 0, age <= maximumAgeSeconds else {
      throw .expired
    }
    let issuedAt: VerificationInstant
    do {
      issuedAt = try VerificationInstant(
        secondsSinceUnixEpoch: issuedSeconds,
        nanoseconds: 0
      )
    } catch {
      throw .malformedCookie
    }
    return DTLS13CookieValidation(
      clientHelloHash: OwnedBytes(
        copying: cookie.extracting(
          Self.headerByteCount..<payloadByteCount
        )
      ),
      cipherSuite: cipherSuite,
      issuedAt: issuedAt
    )
  }

  private borrowing func authenticationCode(
    payload: Span<UInt8>,
    peerIdentity: Span<UInt8>
  ) throws(DTLS13CookieError) -> OwnedBytes {
    var authenticatedInput = ContiguousArray<UInt8>()
    authenticatedInput.reserveCapacity(
      Self.domain.count + 2 + peerIdentity.count + payload.count
    )
    Self.append(Self.domain.span, to: &authenticatedInput)
    authenticatedInput.append(
      UInt8(truncatingIfNeeded: peerIdentity.count >> 8)
    )
    authenticatedInput.append(UInt8(truncatingIfNeeded: peerIdentity.count))
    Self.append(peerIdentity, to: &authenticatedInput)
    Self.append(payload, to: &authenticatedInput)
    var tag = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA256.tagByteCount
    )
    do {
      try key.withBorrowedBytes { keyBytes throws(CryptoInputError) in
        try tag.withUnsafeMutableBufferPointer {
          buffer throws(CryptoInputError) in
          var output = MutableSpan(
            _unsafeStart: buffer.baseAddress!,
            count: buffer.count
          )
          try HMACSHA256.authenticate(
            authenticatedInput.span,
            using: keyBytes,
            into: &output
          )
        }
      }
    } catch {
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: tag)
  }

  private borrowing func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>,
    payload: Span<UInt8>,
    peerIdentity: Span<UInt8>
  ) throws(DTLS13CookieError) -> Bool {
    let expected = try self.authenticationCode(
      payload: payload,
      peerIdentity: peerIdentity
    )
    return ConstantTime.equal(expected.span, authenticationCode)
  }

  private static func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  private static func appendUInt64(
    _ value: UInt64,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var shift = 56
    while shift >= 0 {
      destination.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
      shift -= 8
    }
  }

  private static func readUInt64(_ bytes: Span<UInt8>) -> UInt64 {
    var value: UInt64 = 0
    var index = 0
    while index < bytes.count {
      value = value << 8 | UInt64(bytes[index])
      index += 1
    }
    return value
  }
}
