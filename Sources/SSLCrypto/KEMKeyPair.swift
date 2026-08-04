@frozen
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

  /// Transfers both key owners through one consuming closure.
  ///
  /// Keeping the two fields in one consuming operation avoids partially
  /// consuming a noncopyable key pair at an adapter boundary.
  public consuming func withConsumedKeys<Result: ~Copyable>(
    _ body: (consuming PublicKey, consuming PrivateKey) -> Result
  ) -> Result {
    body(publicKey, privateKey)
  }
}
