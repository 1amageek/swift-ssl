import SSLCore
import SSLCrypto

/// FIPS 204 ML-DSA-44 exposed through SSL-owned key types.
public enum MLDSA44: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA44PublicKey
  public typealias PrivateKey = MLDSA44PrivateKey

  public static let seedByteCount = SSLCrypto.MLDSA44.seedByteCount
  public static let publicKeyByteCount = SSLCrypto.MLDSA44.publicKeyByteCount
  public static let privateKeyByteCount = SSLCrypto.MLDSA44.privateKeyByteCount
  public static let signatureByteCount = SSLCrypto.MLDSA44.signatureByteCount
  public static let randomizerByteCount = SSLCrypto.MLDSA44.randomizerByteCount
  public static let maximumContextByteCount = SSLCrypto.MLDSA44.maximumContextByteCount

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA44KeyPair {
    let pair: SSLCrypto.MLDSA44KeyPair
    do {
      pair = try SSLCrypto.MLDSA44.keyPair(using: entropy)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA44KeyPair(
      publicKey: MLDSA44PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA44PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA44KeyPair {
    let pair: SSLCrypto.MLDSA44KeyPair
    do {
      pair = try SSLCrypto.MLDSA44.keyPair()
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA44KeyPair(
      publicKey: MLDSA44PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA44PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA44KeyPair {
    let pair: SSLCrypto.MLDSA44KeyPair
    do {
      pair = try SSLCrypto.MLDSA44.keyPair(seed: seed)
    } catch {
      throw MLDSAError(error)
    }
    return MLDSA44KeyPair(
      publicKey: MLDSA44PublicKey(implementation: pair.publicKey),
      privateKey: MLDSA44PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SSLCrypto.MLDSA44.sign(
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
    using privateKey: borrowing MLDSA44PrivateKey
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    do {
      return try SSLCrypto.MLDSA44.sign(
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
    using privateKey: borrowing MLDSA44PrivateKey,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SSLCrypto.MLDSA44.sign(
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
    using privateKey: borrowing MLDSA44PrivateKey,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    do {
      try SSLCrypto.MLDSA44.sign(
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
    using publicKey: borrowing MLDSA44PublicKey
  ) throws(MLDSAError) -> Bool {
    do {
      return try SSLCrypto.MLDSA44.verify(
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
