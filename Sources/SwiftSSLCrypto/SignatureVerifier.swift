import SwiftSSLCore

public protocol SignatureVerifier: Sendable {
  associatedtype PublicKey: Sendable

  static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    using publicKey: borrowing PublicKey
  ) throws(CryptoInputError) -> Bool
}

/// Message signing and verification with distinct private and public owners.
///
/// Conformance means that the same algorithm owns both capabilities. A
/// verification-only compatibility algorithm conforms to
/// `DigestSignatureVerifier` instead and therefore cannot be selected by a
/// protocol signer.
public protocol DigitalSignature: SignatureVerifier {
  associatedtype PrivateKey: ~Copyable & Sendable

  static func sign(
    message: Span<UInt8>,
    using privateKey: borrowing PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8>
}
