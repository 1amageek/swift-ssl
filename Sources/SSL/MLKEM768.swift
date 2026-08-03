import SSLCrypto

/// FIPS 203 ML-KEM-768 exposed through SSL-owned key and result types.
public enum MLKEM768: InPlaceKeyEncapsulationMechanism {
  public static let encapsulationByteCount = Encapsulation.byteCount
  public static let sharedSecretByteCount = SharedSecret.byteCount

  public struct PublicKey: Sendable, Equatable {
    public static let byteCount = SSLCrypto.MLKEM768.PublicKey.byteCount
    fileprivate let implementation: SSLCrypto.MLKEM768.PublicKey

    public init(bytes: Span<UInt8>) throws(KEMError) {
      do {
        implementation = try SSLCrypto.MLKEM768.PublicKey(bytes: bytes)
      } catch {
        throw KEMError(error)
      }
    }

    fileprivate init(implementation: SSLCrypto.MLKEM768.PublicKey) {
      self.implementation = implementation
    }

    public var span: Span<UInt8> { implementation.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try implementation.withBorrowedBytes(body)
    }
  }

  public struct PrivateKey: ~Copyable, Sendable {
    public static let byteCount = SSLCrypto.MLKEM768.PrivateKey.byteCount
    fileprivate let implementation: SSLCrypto.MLKEM768.PrivateKey

    public init(bytes: Span<UInt8>) throws(KEMError) {
      do {
        implementation = try SSLCrypto.MLKEM768.PrivateKey(bytes: bytes)
      } catch {
        throw KEMError(error)
      }
    }

    fileprivate init(implementation: consuming SSLCrypto.MLKEM768.PrivateKey) {
      self.implementation = implementation
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try implementation.withBorrowedBytes(body)
    }
  }

  public struct Encapsulation: Sendable, Equatable {
    public static let byteCount = SSLCrypto.MLKEM768.Encapsulation.byteCount
    fileprivate let implementation: SSLCrypto.MLKEM768.Encapsulation

    public init(bytes: Span<UInt8>) throws(KEMError) {
      do {
        implementation = try SSLCrypto.MLKEM768.Encapsulation(bytes: bytes)
      } catch {
        throw KEMError(error)
      }
    }

    fileprivate init(implementation: SSLCrypto.MLKEM768.Encapsulation) {
      self.implementation = implementation
    }

    public var span: Span<UInt8> { implementation.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try implementation.withBorrowedBytes(body)
    }
  }

  public struct SharedSecret: ~Copyable, Sendable {
    public static let byteCount = SSLCrypto.MLKEM768.SharedSecret.byteCount
    fileprivate let implementation: SSLCrypto.MLKEM768.SharedSecret

    fileprivate init(implementation: consuming SSLCrypto.MLKEM768.SharedSecret) {
      self.implementation = implementation
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try implementation.withBorrowedBytes(body)
    }
  }

  public static func generateKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
    let pair:
      SSLCrypto.KEMKeyPair<
        SSLCrypto.MLKEM768.PublicKey,
        SSLCrypto.MLKEM768.PrivateKey
      >
    do {
      pair = try SSLCrypto.MLKEM768.generateKeyPair(using: entropy)
    } catch {
      throw KEMError(error)
    }
    return KEMKeyPair(
      publicKey: PublicKey(implementation: pair.publicKey),
      privateKey: PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func generateKeyPair() throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
    let pair:
      SSLCrypto.KEMKeyPair<
        SSLCrypto.MLKEM768.PublicKey,
        SSLCrypto.MLKEM768.PrivateKey
      >
    do {
      pair = try SSLCrypto.MLKEM768.generateKeyPair()
    } catch {
      throw KEMError(error)
    }
    return KEMKeyPair(
      publicKey: PublicKey(implementation: pair.publicKey),
      privateKey: PrivateKey(implementation: pair.privateKey)
    )
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
    let result:
      SSLCrypto.EncapsulationResult<
        SSLCrypto.MLKEM768.Encapsulation,
        SSLCrypto.MLKEM768.SharedSecret
      >
    do {
      result = try SSLCrypto.MLKEM768.encapsulate(
        to: publicKey.implementation,
        using: entropy
      )
    } catch {
      throw KEMError(error)
    }
    return EncapsulationResult(
      encapsulation: Encapsulation(implementation: result.encapsulation),
      sharedSecret: SharedSecret(implementation: result.sharedSecret)
    )
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
    let result:
      SSLCrypto.EncapsulationResult<
        SSLCrypto.MLKEM768.Encapsulation,
        SSLCrypto.MLKEM768.SharedSecret
      >
    do {
      result = try SSLCrypto.MLKEM768.encapsulate(to: publicKey.implementation)
    } catch {
      throw KEMError(error)
    }
    return EncapsulationResult(
      encapsulation: Encapsulation(implementation: result.encapsulation),
      sharedSecret: SharedSecret(implementation: result.sharedSecret)
    )
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    do {
      try SSLCrypto.MLKEM768.encapsulate(
        to: publicKey.implementation,
        using: entropy,
        into: &encapsulation,
        sharedSecret: &sharedSecret
      )
    } catch {
      throw KEMError(error)
    }
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    do {
      try SSLCrypto.MLKEM768.encapsulate(
        to: publicKey.implementation,
        into: &encapsulation,
        sharedSecret: &sharedSecret
      )
    } catch {
      throw KEMError(error)
    }
  }

  public static func decapsulate(
    _ encapsulation: borrowing Encapsulation,
    using privateKey: borrowing PrivateKey
  ) throws(KEMError) -> SharedSecret {
    do {
      return SharedSecret(
        implementation: try SSLCrypto.MLKEM768.decapsulate(
          encapsulation.implementation,
          using: privateKey.implementation
        )
      )
    } catch {
      throw KEMError(error)
    }
  }

  public static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing PrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    do {
      try SSLCrypto.MLKEM768.decapsulate(
        encapsulation,
        using: privateKey.implementation,
        into: &sharedSecret
      )
    } catch {
      throw KEMError(error)
    }
  }
}
