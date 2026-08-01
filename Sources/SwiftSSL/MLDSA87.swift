import SwiftSSLCore
import SwiftSSLCrypto

/// FIPS 204 ML-DSA-87 exposed through SwiftSSL-owned key types.
public enum MLDSA87: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA87PublicKey
  public typealias PrivateKey = MLDSA87PrivateKey

  public static let seedByteCount = SwiftSSLCrypto.MLDSA87.seedByteCount
  public static let publicKeyByteCount = SwiftSSLCrypto.MLDSA87.publicKeyByteCount
  public static let privateKeyByteCount = SwiftSSLCrypto.MLDSA87.privateKeyByteCount
  public static let signatureByteCount = SwiftSSLCrypto.MLDSA87.signatureByteCount
  public static let randomizerByteCount = SwiftSSLCrypto.MLDSA87.randomizerByteCount
  public static let maximumContextByteCount = SwiftSSLCrypto.MLDSA87.maximumContextByteCount

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA87KeyPair {
    let pair: SwiftSSLCrypto.MLDSA87KeyPair
    do {
      pair = try SwiftSSLCrypto.MLDSA87.keyPair(using: entropy)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA87KeyPair(
      publicKey: MLDSA87PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA87PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA87KeyPair {
    let pair: SwiftSSLCrypto.MLDSA87KeyPair
    do {
      pair = try SwiftSSLCrypto.MLDSA87.keyPair()
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA87KeyPair(
      publicKey: MLDSA87PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA87PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA87KeyPair {
    let pair: SwiftSSLCrypto.MLDSA87KeyPair
    do {
      pair = try SwiftSSLCrypto.MLDSA87.keyPair(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA87KeyPair(
      publicKey: MLDSA87PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA87PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SwiftSSLCrypto.MLDSA87.sign(
        message: message,
        context: context,
        using: privateKey.implementation,
        entropy: entropy
      )
    } catch {
      throw MLDSAError(error)
    }
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SwiftSSLCrypto.MLDSA87.sign(
        message: message,
        context: context,
        using: privateKey.implementation
      )
    } catch {
      throw MLDSAError(error)
    }
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SwiftSSLCrypto.MLDSA87.sign(
        message: message,
        context: context,
        using: privateKey.implementation,
        entropy: entropy,
        into: &signature
      )
    } catch {
      throw MLDSAError(error)
    }
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SwiftSSLCrypto.MLDSA87.sign(
        message: message,
        context: context,
        using: privateKey.implementation,
        into: &signature
      )
    } catch {
      throw MLDSAError(error)
    }
  }

  public static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using publicKey: borrowing MLDSA87PublicKey
  ) throws(MLDSAError) -> Bool {
    do {
      return try SwiftSSLCrypto.MLDSA87.verify(
        signature: signature,
        message: message,
        context: context,
        using: publicKey.implementation
      )
    } catch {
      throw MLDSAError(error)
    }
  }
}
