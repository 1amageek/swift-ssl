import SwiftSSLCore
import SwiftSSLCrypto

/// A noncopyable SwiftSSL owner for a FIPS 204 ML-DSA-87 private key.
public struct MLDSA87PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SwiftSSLCrypto.MLDSA87PrivateKey.byteCount
  public static let seedByteCount = SwiftSSLCrypto.MLDSA87PrivateKey.seedByteCount

  let implementation: SwiftSSLCrypto.MLDSA87PrivateKey

  public init(seed: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SwiftSSLCrypto.MLDSA87PrivateKey(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
  }

  public init(encoded: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SwiftSSLCrypto.MLDSA87PrivateKey(encoded: encoded)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: consuming SwiftSSLCrypto.MLDSA87PrivateKey) {
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
