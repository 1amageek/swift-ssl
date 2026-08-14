
/// Key agreement that borrows an encoded peer key and writes into caller-owned storage.
public protocol InPlaceEncodedKeyAgreement: KeyAgreement {
  static var sharedSecretByteCount: Int { get }

  static func sharedSecret(
    privateKey: borrowing PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)
}
