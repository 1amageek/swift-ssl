import SSLCore
import SSLCrypto

public struct TLS13X25519ClientKeyExchange: TLS13ClientKeyExchange, ~Copyable, Sendable {
    private let share: OwnedBytes
    private var privateKey: X25519PrivateKey?

    public init(privateKey: consuming X25519PrivateKey) {
        share = OwnedBytes(copying: privateKey.publicKey().span)
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

    /// Returns an immutable owner sharing the key-share backing storage.
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
        let peerKey: X25519PublicKey
        do {
            peerKey = try X25519PublicKey(bytes: serverShare)
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
        return component.withBorrowedBytes { bytes in
            SecretBytes(byteCount: byteCount) { destination in
                Self.copy(bytes, into: &destination, outputOffset: 0)
            }
        }
    }

    private static func copy(
        _ source: Span<UInt8>,
        into destination: inout MutableSpan<UInt8>,
        outputOffset: Int
    ) {
        var index = 0
        while index < source.count {
            destination[outputOffset + index] = source[index]
            index += 1
        }
    }
}
