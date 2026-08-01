@frozen public struct MLDSA44KeyPair: ~Copyable, Sendable {
  public let publicKey: MLDSA44PublicKey
  public let privateKey: MLDSA44PrivateKey

  init(
    publicKey: consuming MLDSA44PublicKey,
    privateKey: consuming MLDSA44PrivateKey
  ) {
    self.publicKey = publicKey
    self.privateKey = privateKey
  }
}
