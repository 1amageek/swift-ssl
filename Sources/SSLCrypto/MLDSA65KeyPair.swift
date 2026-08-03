@frozen public struct MLDSA65KeyPair: ~Copyable, Sendable {
  public let publicKey: MLDSA65PublicKey
  public let privateKey: MLDSA65PrivateKey

  init(
    publicKey: consuming MLDSA65PublicKey,
    privateKey: consuming MLDSA65PrivateKey
  ) {
    self.publicKey = publicKey
    self.privateKey = privateKey
  }
}
