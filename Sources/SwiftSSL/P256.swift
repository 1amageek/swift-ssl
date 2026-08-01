import SwiftSSLCore
import SwiftSSLCrypto

/// Verification-only P-256 ECDSA exposed by the SwiftSSL façade.
public enum P256ECDSA {
  public static let signatureByteCount = SwiftSSLCrypto.P256ECDSA.signatureByteCount

  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    publicKey: borrowing P256PublicKey
  ) throws(CryptoInputError) -> Bool {
    do {
      return try SwiftSSLCrypto.P256ECDSA.verify(
        signature: signature,
        messageHash: messageHash,
        using: publicKey.implementation
      )
    } catch {
      throw CryptoInputError(error)
    }
  }
}

/// An owned, validated SEC1 uncompressed P-256 public key.
public struct P256PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount = SwiftSSLCrypto.P256PublicKey.uncompressedByteCount
  fileprivate let implementation: SwiftSSLCrypto.P256PublicKey

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    do {
      implementation = try SwiftSSLCrypto.P256PublicKey(bytes: bytes)
    } catch {
      throw CryptoInputError(error)
    }
  }

  public var span: Span<UInt8> { implementation.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}
