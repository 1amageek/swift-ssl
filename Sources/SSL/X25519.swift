import SSLCore
import SSLCrypto

/// RFC 7748 X25519 key agreement exposed by the SSL façade.
public enum X25519 {
  public static func sharedSecret(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey
  ) throws(CryptoInputError) -> X25519SharedSecret {
    let implementation: SSLCrypto.X25519SharedSecret
    do {
      implementation = try SSLCrypto.X25519.sharedSecret(
        privateKey: privateKey.implementation,
        peerPublicKey: peerPublicKey.implementation
      )
    } catch {
      throw CryptoInputError(error)
    }
    return X25519SharedSecret(implementation: implementation)
  }
}

public struct X25519PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SSLCrypto.X25519PrivateKey.byteCount

  fileprivate let implementation: SSLCrypto.X25519PrivateKey

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(X25519KeyGenerationError) -> X25519PrivateKey {
    do {
      return X25519PrivateKey(
        implementation: try SSLCrypto.X25519PrivateKey.generate(using: entropy)
      )
    } catch let error {
      switch error {
      case .entropy(let value):
        throw .entropy(value)
      case .memoryFailure:
        throw .memoryFailure
      }
    }
  }

  public static func generate() throws(X25519KeyGenerationError) -> X25519PrivateKey {
    do {
      return X25519PrivateKey(
        implementation: try SSLCrypto.X25519PrivateKey.generate()
      )
    } catch let error {
      switch error {
      case .entropy(let value):
        throw .entropy(value)
      case .memoryFailure:
        throw .memoryFailure
      }
    }
  }

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    do {
      implementation = try SSLCrypto.X25519PrivateKey(bytes: bytes)
    } catch {
      throw CryptoInputError(error)
    }
  }

  fileprivate init(implementation: consuming SSLCrypto.X25519PrivateKey) {
    self.implementation = implementation
  }

  public borrowing func publicKey() -> X25519PublicKey {
    X25519PublicKey(implementation: implementation.publicKey())
  }
}

public struct X25519PublicKey: Sendable, Equatable {
  public static let byteCount = SSLCrypto.X25519PublicKey.byteCount

  fileprivate let implementation: SSLCrypto.X25519PublicKey

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    do {
      implementation = try SSLCrypto.X25519PublicKey(bytes: bytes)
    } catch {
      throw CryptoInputError(error)
    }
  }

  fileprivate init(implementation: SSLCrypto.X25519PublicKey) {
    self.implementation = implementation
  }

  public var span: Span<UInt8> { implementation.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}

public struct X25519SharedSecret: ~Copyable, Sendable {
  public static let byteCount = SSLCrypto.X25519SharedSecret.byteCount

  private let implementation: SSLCrypto.X25519SharedSecret

  fileprivate init(implementation: consuming SSLCrypto.X25519SharedSecret) {
    self.implementation = implementation
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try implementation.withBorrowedBytes(body)
  }
}
