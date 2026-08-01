import SwiftSSLCore
import SwiftSSLCrypto

/// A noncopyable owner for a FIPS 204 ML-DSA-65 private key.
public struct MLDSA65PrivateKey: ~Copyable, Sendable {
  public static let byteCount = SwiftSSLCrypto.MLDSA65PrivateKey.byteCount
  public static let seedByteCount = SwiftSSLCrypto.MLDSA65PrivateKey.seedByteCount

  let implementation: SwiftSSLCrypto.MLDSA65PrivateKey

  public init(seed: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SwiftSSLCrypto.MLDSA65PrivateKey(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
  }

  public init(encoded: Span<UInt8>) throws(MLDSAError) {
    do {
      implementation = try SwiftSSLCrypto.MLDSA65PrivateKey(encoded: encoded)
    } catch {
      throw MLDSAError(error)
    }
  }

  init(implementation: consuming SwiftSSLCrypto.MLDSA65PrivateKey) {
    self.implementation = implementation
  }

  public borrowing func publicKey() throws(MLDSAError) -> MLDSA65PublicKey {
    do {
      return MLDSA65PublicKey(implementation: try implementation.publicKey())
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
