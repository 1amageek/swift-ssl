import SSLCore
import SSLCrypto

/// Client-side TLS 1.3 secp256r1 key exchange with unique scalar ownership.
public struct TLS13P256ClientKeyExchange:
  TLS13ClientKeyExchange, ~Copyable, Sendable
{
  private let share: OwnedBytes
  private var privateKey: P256PrivateKey?

  public init(privateKey: consuming P256PrivateKey) {
    share = OwnedBytes(copying: privateKey.publicKey().span)
    self.privateKey = consume privateKey
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(TLS13KeyExchangeError) -> Self {
    do {
      return Self(privateKey: try P256PrivateKey.generate(using: entropy))
    } catch let error {
      throw .p256KeyGeneration(error)
    }
  }

  public var namedGroup: TLS13NamedGroup { .secp256r1 }

  public borrowing func clientShare() -> OwnedBytes {
    share
  }

  public borrowing func withClientShare<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(share.span)
  }

  public mutating func complete(
    serverShare: Span<UInt8>
  ) throws(TLS13KeyExchangeError) -> SecretBytes {
    guard serverShare.count == namedGroup.serverShareByteCount else {
      throw .invalidShareLength(
        expected: namedGroup.serverShareByteCount,
        actual: serverShare.count
      )
    }
    guard let privateKey = privateKey.take() else {
      throw .invalidState
    }
    let peerKey: P256PublicKey
    do {
      peerKey = try P256PublicKey(bytes: serverShare)
    } catch let error {
      throw .crypto(error)
    }
    let component: P256SharedSecret
    do {
      component = try P256KeyAgreement.sharedSecret(
        privateKey: privateKey,
        peerPublicKey: peerKey
      )
    } catch let error {
      throw .crypto(error)
    }
    return try Self.copySecret(component)
  }

  private static func copySecret(
    _ component: borrowing P256SharedSecret
  ) throws(TLS13KeyExchangeError) -> SecretBytes {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(P256SharedSecret.byteCount)
    } catch let error {
      throw .secretMemory(error)
    }
    return component.withBorrowedBytes { source in
      SecretBytes(byteCount: byteCount) { destination in
        var index = 0
        while index < source.count {
          destination[index] = source[index]
          index += 1
        }
      }
    }
  }
}
