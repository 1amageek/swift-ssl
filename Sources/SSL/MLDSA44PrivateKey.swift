import SSLCore
import SSLCrypto

/// A noncopyable SSL owner for a FIPS 204 ML-DSA-44 private key.
public struct MLDSA44PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SSLCrypto.MLDSA44PrivateKey.byteCount
  public static let seedByteCount = SSLCrypto.MLDSA44PrivateKey.seedByteCount

  let implementation: SSLCrypto.MLDSA44PrivateKey

  public init(seed: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA44PrivateKey(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
  }

  public init(encoded: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA44PrivateKey(encoded: encoded)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: consuming SSLCrypto.MLDSA44PrivateKey) {
    self.implementation = implementation
  }

  public borrowing func publicKey() throws(MLDSAError) -> MLDSA44PublicKey {
    do {
      return MLDSA44PublicKey(implementation: try implementation.publicKey())
    } catch {
      throw MLDSAError(error)
    }
  }

  public borrowing func standardRepresentation() throws(MLDSAError) -> SecretBytes {
    do {
      return try implementation.standardRepresentation()
    } catch {
      throw MLDSAError(error)
    }
  }
}
