@frozen public struct MLDSA87KeyPair: ~Copyable, Sendable {
  public let publicKey: MLDSA87PublicKey
  public let privateKey: MLDSA87PrivateKey

  init(
    publicKey: consuming MLDSA87PublicKey,
    privateKey: consuming MLDSA87PrivateKey
  ) {
    self.publicKey = publicKey
    self.privateKey = privateKey
  }
}
