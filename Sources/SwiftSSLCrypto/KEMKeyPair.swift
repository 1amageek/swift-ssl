public struct KEMKeyPair<
  PublicKey: Sendable,
  PrivateKey: ~Copyable & Sendable
>: ~Copyable, Sendable {
  public let publicKey: PublicKey
  public let privateKey: PrivateKey

  public init(publicKey: consuming PublicKey, privateKey: consuming PrivateKey) {
    self.publicKey = publicKey
    self.privateKey = privateKey
  }
}
