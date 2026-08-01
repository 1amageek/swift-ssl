import SwiftSSLCore

/// Key agreement that writes directly into caller-owned secret storage.
public protocol InPlaceKeyAgreement: KeyAgreement {
  static var sharedSecretByteCount: Int { get }

  static func sharedSecret(
    privateKey: borrowing PrivateKey,
    peerPublicKey: borrowing PublicKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)
}
