
/// Verification-only signature algorithm over a caller-provided digest.
///
/// Digest selection and signature-container decoding belong to the protocol
/// layer. This capability intentionally has no signing requirement.
public protocol DigestSignatureVerifier: Sendable {
  associatedtype PublicKey: Sendable

  static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing PublicKey
  ) throws(CryptoInputError) -> Bool
}
