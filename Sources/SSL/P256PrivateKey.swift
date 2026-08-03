import SSLCore
import SSLCrypto

/// A noncopyable, wipe-on-destroy P-256 private scalar.
public struct P256PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SSLCrypto.P256PrivateKey.byteCount

  let implementation: SSLCrypto.P256PrivateKey

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    do {
      implementation = try SSLCrypto.P256PrivateKey(bytes: bytes)
    } catch {
      throw CryptoInputError(error)
    }
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(P256KeyGenerationError) -> P256PrivateKey {
    do {
      return P256PrivateKey(
        implementation: try SSLCrypto.P256PrivateKey.generate(
          using: entropy
        )
      )
    } catch let error {
      switch error {
      case .entropy(let value):
        throw .entropy(value)
      case .invalidScalar:
        throw .invalidScalar
      }
    }
  }

  public static func generate() throws(P256KeyGenerationError) -> P256PrivateKey {
    do {
      return P256PrivateKey(
        implementation: try SSLCrypto.P256PrivateKey.generate()
      )
    } catch let error {
      switch error {
      case .entropy(let value):
        throw .entropy(value)
      case .invalidScalar:
        throw .invalidScalar
      }
    }
  }

  init(implementation: consuming SSLCrypto.P256PrivateKey) {
    self.implementation = implementation
  }

  public borrowing func publicKey() -> P256PublicKey {
    P256PublicKey(implementation: implementation.publicKey())
  }
}
