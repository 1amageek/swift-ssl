import SSLCore
import SSLCrypto

/// An owned SSL FIPS 204 ML-DSA-44 public key.
public struct MLDSA44PublicKey: Sendable, Equatable {
  public static let byteCount = SSLCrypto.MLDSA44PublicKey.byteCount

  let implementation: SSLCrypto.MLDSA44PublicKey

  public init(bytes: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA44PublicKey(bytes: bytes)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: SSLCrypto.MLDSA44PublicKey) {
    self.implementation = implementation
  }

  public var span: Span<UInt8> { implementation.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}
