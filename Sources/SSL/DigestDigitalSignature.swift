import SSLCore

/// Verifies signatures over caller-selected digests.
public protocol DigestSignatureVerifier: Sendable {
  associatedtype PublicKey: Sendable

  static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing PublicKey
  ) throws(CryptoInputError) -> Bool
}

/// Signs and verifies caller-selected digests with separate key owners.
public protocol DigestDigitalSignature: DigestSignatureVerifier {
  associatedtype PrivateKey: ~Copyable & Sendable

  static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8>
}
