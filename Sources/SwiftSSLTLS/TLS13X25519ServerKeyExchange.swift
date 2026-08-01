import SwiftSSLCore
import SwiftSSLCrypto

public struct TLS13X25519ServerKeyExchange: TLS13ServerKeyExchange, ~Copyable, Sendable {
    private var privateKey: X25519PrivateKey?

    public init(privateKey: consuming X25519PrivateKey) {
        self.privateKey = consume privateKey
    }

    public static func generate(
        using entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> Self {
        do {
            return Self(privateKey: try X25519PrivateKey.generate(using: entropy))
        } catch let error {
            throw .x25519KeyGeneration(error)
        }
    }

    public var namedGroup: TLS13NamedGroup { .x25519 }

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
        let peerKey: X25519PublicKey
        do {
            peerKey = try X25519PublicKey(bytes: clientShare)
        } catch let error {
            throw .crypto(error)
        }
        let component: X25519SharedSecret
        do {
            component = try X25519.sharedSecret(
                privateKey: privateKey,
                peerPublicKey: peerKey
            )
        } catch let error {
            throw .crypto(error)
        }
        let byteCount: SecretByteCount
        do {
            byteCount = try SecretByteCount(namedGroup.sharedSecretByteCount)
        } catch let error {
            throw .secretMemory(error)
        }
        let secret = component.withBorrowedBytes { bytes in
            SecretBytes(byteCount: byteCount) { destination in
                Self.copy(bytes, into: &destination)
            }
        }
        return TLS13ServerKeyExchangeResult(
            serverShare: OwnedBytes(copying: privateKey.publicKey().span),
            sharedSecret: secret
        )
    }

    private static func copy(
        _ source: Span<UInt8>,
        into destination: inout MutableSpan<UInt8>
    ) {
        var index = 0
        while index < source.count {
            destination[index] = source[index]
            index += 1
        }
    }
}
