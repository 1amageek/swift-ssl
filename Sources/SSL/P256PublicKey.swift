import SSLCore
import SSLCrypto

/// An owned, validated SEC 1 uncompressed P-256 public key.
public struct P256PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount =
    SSLCrypto.P256PublicKey.uncompressedByteCount

  let implementation: SSLCrypto.P256PublicKey

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    do {
      implementation = try SSLCrypto.P256PublicKey(bytes: bytes)
    } catch {
      throw CryptoInputError(error)
    }
  }

  init(implementation: SSLCrypto.P256PublicKey) {
    self.implementation = implementation
  }

  public var span: Span<UInt8> { implementation.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}
