import SSLCore
import SSLCrypto

/// FIPS 204 ML-DSA-65 exposed through SSL-owned key types.
public enum MLDSA65: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA65PublicKey
  public typealias PrivateKey = MLDSA65PrivateKey

  public static let seedByteCount = SSLCrypto.MLDSA65.seedByteCount
  public static let publicKeyByteCount = SSLCrypto.MLDSA65.publicKeyByteCount
  public static let privateKeyByteCount = SSLCrypto.MLDSA65.privateKeyByteCount
  public static let signatureByteCount = SSLCrypto.MLDSA65.signatureByteCount
  public static let randomizerByteCount = SSLCrypto.MLDSA65.randomizerByteCount
  public static let maximumContextByteCount = SSLCrypto.MLDSA65.maximumContextByteCount

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA65KeyPair {
    let pair: SSLCrypto.MLDSA65KeyPair
    do {
      pair = try SSLCrypto.MLDSA65.keyPair(using: entropy)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA65KeyPair(
      publicKey: MLDSA65PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA65PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA65KeyPair {
    let pair: SSLCrypto.MLDSA65KeyPair
    do {
      pair = try SSLCrypto.MLDSA65.keyPair()
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA65KeyPair(
      publicKey: MLDSA65PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA65PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA65KeyPair {
    let pair: SSLCrypto.MLDSA65KeyPair
    do {
      pair = try SSLCrypto.MLDSA65.keyPair(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA65KeyPair(
      publicKey: MLDSA65PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA65PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA65PrivateKey,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SSLCrypto.MLDSA65.sign(
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
    using privateKey: borrowing MLDSA65PrivateKey
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SSLCrypto.MLDSA65.sign(
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
    using privateKey: borrowing MLDSA65PrivateKey,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SSLCrypto.MLDSA65.sign(
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
    using privateKey: borrowing MLDSA65PrivateKey,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SSLCrypto.MLDSA65.sign(
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
    using publicKey: borrowing MLDSA65PublicKey
  ) throws(MLDSAError) -> Bool {
    do {
      return try SSLCrypto.MLDSA65.verify(
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
