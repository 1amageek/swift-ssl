import SSLCore
import SSLCrypto

/// An owned FIPS 204 ML-DSA-65 public key.
public struct MLDSA65PublicKey: Sendable, Equatable {
  public static let byteCount = SSLCrypto.MLDSA65PublicKey.byteCount

  let implementation: SSLCrypto.MLDSA65PublicKey

  public init(bytes: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA65PublicKey(bytes: bytes)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: SSLCrypto.MLDSA65PublicKey) {
    self.implementation = implementation
  }

  public var span: Span<UInt8> { implementation.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}
