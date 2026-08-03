import SSLCore
import SSLCrypto

/// A noncopyable SSL owner for a FIPS 204 ML-DSA-87 private key.
public struct MLDSA87PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SSLCrypto.MLDSA87PrivateKey.byteCount
  public static let seedByteCount = SSLCrypto.MLDSA87PrivateKey.seedByteCount

  let implementation: SSLCrypto.MLDSA87PrivateKey

  public init(seed: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA87PrivateKey(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
  }

  public init(encoded: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SSLCrypto.MLDSA87PrivateKey(encoded: encoded)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: consuming SSLCrypto.MLDSA87PrivateKey) {
    self.implementation = implementation
  }

  public borrowing func publicKey() throws(MLDSAError) -> MLDSA87PublicKey {
    do {
      return MLDSA87PublicKey(implementation: try implementation.publicKey())
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
