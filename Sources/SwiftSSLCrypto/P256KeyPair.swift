import SwiftSSLCore

/// A P-256 private scalar paired with its precomputed public key.
@frozen
public struct P256KeyPair: ~Copyable, Sendable {
  public let publicKey: P256PublicKey
  public let privateKey: P256PrivateKey

  public init(privateKey: consuming P256PrivateKey) {
    publicKey = privateKey.publicKey()
    self.privateKey = privateKey
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(P256KeyGenerationError) -> P256KeyPair {
    let privateKey = try P256PrivateKey.generate(using: entropy)
    return P256KeyPair(privateKey: privateKey)
  }

  public static func generate() throws(P256KeyGenerationError) -> P256KeyPair {
    let privateKey = try P256PrivateKey.generate()
    return P256KeyPair(privateKey: privateKey)
  }
}
