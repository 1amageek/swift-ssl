import SSLCore
import SSLCrypto

/// Server-side TLS 1.3 secp256r1 key exchange with unique scalar ownership.
public struct TLS13P256ServerKeyExchange:
  TLS13ServerKeyExchange, ~Copyable, Sendable
{
  private var privateKey: P256PrivateKey?

  public init(privateKey: consuming P256PrivateKey) {
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

  public mutating func accept(
    clientShare: Span<UInt8>,
    using entropy: borrowing any EntropySource
  ) throws(TLS13KeyExchangeError) -> TLS13ServerKeyExchangeResult {
    _ = entropy
    guard clientShare.count == namedGroup.clientShareByteCount else {
      throw .invalidShareLength(
        expected: namedGroup.clientShareByteCount,
        actual: clientShare.count
      )
    }
    guard let privateKey = privateKey.take() else {
      throw .invalidState
    }
    let peerKey: P256PublicKey
    do {
      peerKey = try P256PublicKey(bytes: clientShare)
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
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(P256SharedSecret.byteCount)
    } catch let error {
      throw .secretMemory(error)
    }
    let secret = component.withBorrowedBytes { source in
      SecretBytes(byteCount: byteCount) { destination in
        var index = 0
        while index < source.count {
          destination[index] = source[index]
          index += 1
        }
      }
    }
    return TLS13ServerKeyExchangeResult(
      serverShare: OwnedBytes(copying: privateKey.publicKey().span),
      sharedSecret: secret
    )
  }
}
