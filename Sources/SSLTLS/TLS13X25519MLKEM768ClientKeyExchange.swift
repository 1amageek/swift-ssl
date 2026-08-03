import SSLCore
import SSLCrypto

public struct TLS13X25519MLKEM768ClientKeyExchange:
    TLS13ClientKeyExchange,
    ~Copyable,
    Sendable
{
    private let share: OwnedBytes
    private var mlkemPrivateKey: MLKEM768.PrivateKey?
    private var x25519PrivateKey: X25519PrivateKey?

    public init(
        mlkemKeyPair: consuming KEMKeyPair<MLKEM768.PublicKey, MLKEM768.PrivateKey>,
        x25519PrivateKey: consuming X25519PrivateKey
    ) throws(TLS13KeyExchangeError) {
        var bytes = ContiguousArray<UInt8>(
            repeating: 0,
            count: TLS13NamedGroup.x25519MLKEM768.clientShareByteCount
        )
        Self.copy(mlkemKeyPair.publicKey.span, into: &bytes, outputOffset: 0)
        do {
            var bytesSpan = bytes.mutableSpan
            var x25519Output = bytesSpan._mutatingExtracting(
                MLKEM768.PublicKey.byteCount..<TLS13NamedGroup.x25519MLKEM768.clientShareByteCount
            )
            try x25519PrivateKey.publicKey(into: &x25519Output)
        } catch let error {
            throw .crypto(error)
        }
        share = OwnedBytes(consuming: bytes)
        mlkemPrivateKey = consume mlkemKeyPair.privateKey
        self.x25519PrivateKey = consume x25519PrivateKey
    }

    public static func generate(
        mlkemEntropy: borrowing any EntropySource,
        x25519Entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> Self {
        let pair: KEMKeyPair<MLKEM768.PublicKey, MLKEM768.PrivateKey>
        do {
            pair = try MLKEM768.generateKeyPair(using: mlkemEntropy)
        } catch let error {
            throw .kem(error)
        }
        let x25519PrivateKey: X25519PrivateKey
        do {
            x25519PrivateKey = try X25519PrivateKey.generate(using: x25519Entropy)
        } catch let error {
            throw .x25519KeyGeneration(error)
        }
        return try Self(
            mlkemKeyPair: pair,
            x25519PrivateKey: x25519PrivateKey
        )
    }

    public var namedGroup: TLS13NamedGroup { .x25519MLKEM768 }

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
        guard
            let mlkemPrivateKey = mlkemPrivateKey.take(),
            let x25519PrivateKey = x25519PrivateKey.take()
        else {
            throw .invalidState
        }
        let x25519Offset = MLKEM768.Encapsulation.byteCount
        let byteCount: SecretByteCount
        do {
            byteCount = try SecretByteCount(namedGroup.sharedSecretByteCount)
        } catch let error {
            throw .secretMemory(error)
        }
        var combinedSecret = SecretBytes(byteCount: byteCount) { _ in }
        do {
            try Self.deriveX25519Secret(
                serverShare.extracting(x25519Offset..<serverShare.count),
                using: x25519PrivateKey,
                into: &combinedSecret
            )
        } catch let error {
            throw .crypto(error)
        }
        do {
            try combinedSecret.withMutableBorrowedBytes {
                output throws(KEMError) in
                var mlkemOutput = output._mutatingExtracting(
                    0..<MLKEM768.SharedSecret.byteCount
                )
                try Self.decapsulate(
                    serverShare.extracting(0..<x25519Offset),
                    using: mlkemPrivateKey,
                    into: &mlkemOutput
                )
            }
        } catch let error {
            throw .kem(error)
        }
        return combinedSecret
    }

    private static func deriveX25519Secret(
        _ peerPublicKey: Span<UInt8>,
        using privateKey: borrowing X25519PrivateKey,
        into combinedSecret: inout SecretBytes
    ) throws(CryptoInputError) {
        try combinedSecret.withMutableBorrowedBytes {
            output throws(CryptoInputError) in
            var x25519Output = output._mutatingExtracting(
                MLKEM768.SharedSecret.byteCount..<output.count
            )
            try X25519.sharedSecret(
                privateKey: privateKey,
                peerPublicKeyBytes: peerPublicKey,
                into: &x25519Output
            )
        }
    }

    private static func decapsulate(
        _ encapsulation: Span<UInt8>,
        using privateKey: borrowing MLKEM768.PrivateKey,
        into sharedSecret: inout MutableSpan<UInt8>
    ) throws(KEMError) {
        try MLKEM768.decapsulate(
            encapsulation,
            using: privateKey,
            into: &sharedSecret
        )
    }

    private static func copy(
        _ source: Span<UInt8>,
        into destination: inout ContiguousArray<UInt8>,
        outputOffset: Int
    ) {
        var index = 0
        while index < source.count {
            destination[outputOffset + index] = source[index]
            index += 1
        }
    }

}
