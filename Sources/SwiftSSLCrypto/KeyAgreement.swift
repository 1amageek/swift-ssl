import SwiftSSLCore

public protocol KeyAgreement: Sendable {
  associatedtype PublicKey: Sendable
  associatedtype PrivateKey: ~Copyable & Sendable
  associatedtype SharedSecret: ~Copyable & Sendable

  static func sharedSecret(
    privateKey: borrowing PrivateKey,
    peerPublicKey: borrowing PublicKey
  ) throws(CryptoInputError) -> SharedSecret
}
