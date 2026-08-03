import SSLCore

/// Context-bound randomized signing and verification capabilities.
public protocol ContextualRandomizedDigitalSignature: Sendable {
  associatedtype PublicKey: Sendable
  associatedtype PrivateKey: ~Copyable & Sendable

  static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing PrivateKey,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8>

  static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using publicKey: borrowing PublicKey
  ) throws(MLDSAError) -> Bool
}
