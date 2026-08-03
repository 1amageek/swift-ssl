import SSLCore
import SSLCrypto

/// One server ECH configuration paired with its noncopyable X25519 key owner.
public struct ECHServerConfiguration: Sendable {
  public let config: ECHConfig
  public let isRetryConfiguration: Bool
  private let keyOwner: ECHServerPrivateKeyOwner

  public init(
    config: ECHConfig,
    privateKey: consuming X25519PrivateKey,
    isRetryConfiguration: Bool = true
  ) throws(ECHError) {
    guard config.kemIdentifier == HPKEX25519.kemIdentifier else {
      throw .unsupportedKEM(config.kemIdentifier)
    }
    guard config.extensions.isEmpty else {
      if let unsupported = config.extensions.first {
        throw .unsupportedMandatoryExtension(unsupported.type)
      }
      throw .malformedConfig
    }
    for suite in config.cipherSuites {
      guard suite.isSupported else {
        throw .unsupportedCipherSuite(
          kdf: suite.kdfIdentifier,
          aead: suite.aeadIdentifier
        )
      }
    }
    let keyOwner = ECHServerPrivateKeyOwner(privateKey: privateKey)
    let publicKeyMatches = keyOwner.keyPair.publicKey.withBorrowedBytes { derived in
      ConstantTime.equal(derived, config.publicKey.span)
    }
    guard publicKeyMatches else {
      throw .publicKeyMismatch
    }
    self.config = config
    self.isRetryConfiguration = isRetryConfiguration
    self.keyOwner = keyOwner
  }

  internal borrowing func withKeyPair<Result: ~Copyable, Failure: Error>(
    _ body: (borrowing X25519KeyPair) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(keyOwner.keyPair)
  }
}

/// Immutable shared ownership permits concurrent handshakes to borrow one
/// server scalar without copying or mutating its secret allocation. The owner
/// releases the noncopyable key exactly once after the final configuration copy.
private final class ECHServerPrivateKeyOwner: @unchecked Sendable {
  let keyPair: X25519KeyPair

  init(privateKey: consuming X25519PrivateKey) {
    keyPair = X25519KeyPair(privateKey: privateKey)
  }
}
