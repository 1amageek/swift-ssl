import SSLCore

/// A noncopyable X25519 private key paired with its precomputed public key.
///
/// Long-lived protocol configurations should own this value so repeated key
/// agreements do not repeat the fixed-base public-key derivation.
@frozen
public struct X25519KeyPair: ~Copyable, Sendable {
  public let publicKey: X25519PublicKey
  public let privateKey: X25519PrivateKey

  public init(privateKey: consuming X25519PrivateKey) {
    publicKey = privateKey.publicKey()
    self.privateKey = privateKey
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(X25519KeyGenerationError) -> X25519KeyPair {
    let privateKey = try X25519PrivateKey.generate(using: entropy)
    return X25519KeyPair(privateKey: privateKey)
  }

  public static func generate() throws(X25519KeyGenerationError) -> X25519KeyPair {
    let privateKey = try X25519PrivateKey.generate()
    return X25519KeyPair(privateKey: privateKey)
  }
}
