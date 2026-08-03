import SSLCore
import SSLCrypto

public protocol DTLS13CookieProtecting: Sendable {
  borrowing func issueCookie(
    clientHelloHash: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    peerIdentity: Span<UInt8>,
    at instant: VerificationInstant
  ) throws(DTLS13CookieError) -> OwnedBytes

  borrowing func validateCookie(
    _ cookie: Span<UInt8>,
    peerIdentity: Span<UInt8>,
    at instant: VerificationInstant
  ) throws(DTLS13CookieError) -> DTLS13CookieValidation
}
