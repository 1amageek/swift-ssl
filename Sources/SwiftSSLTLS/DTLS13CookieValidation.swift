import SwiftSSLCore
import SwiftSSLCrypto

public struct DTLS13CookieValidation: Sendable {
  public let clientHelloHash: OwnedBytes
  public let cipherSuite: TLSCipherSuite
  public let issuedAt: VerificationInstant

  public init(
    clientHelloHash: consuming OwnedBytes,
    cipherSuite: TLSCipherSuite,
    issuedAt: VerificationInstant
  ) {
    self.clientHelloHash = clientHelloHash
    self.cipherSuite = cipherSuite
    self.issuedAt = issuedAt
  }
}
