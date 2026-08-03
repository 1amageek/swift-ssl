import SSLCore
import SSLCrypto

public struct TLS13X25519MLKEM768ServerKeyExchange:
    TLS13ServerKeyExchange,
    ~Copyable,
    Sendable
{
    private var x25519PrivateKey: X25519PrivateKey?

    public init(x25519PrivateKey: consuming X25519PrivateKey) {
        self.x25519PrivateKey = consume x25519PrivateKey
    }

    public static func generate(
        using entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> Self {
        do {
            return Self(x25519PrivateKey: try X25519PrivateKey.generate(using: entropy))
        } catch let error {
            throw .x25519KeyGeneration(error)
        }
    }

    public var namedGroup: TLS13NamedGroup { .x25519MLKEM768 }

    public mutating func accept(
        clientShare: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> TLS13ServerKeyExchangeResult {
        guard clientShare.count == namedGroup.clientShareByteCount else {
            throw .invalidShareLength(
                expected: namedGroup.clientShareByteCount,
                actual: clientShare.count
            )
        }
        guard let x25519PrivateKey = x25519PrivateKey.take() else {
            throw .invalidState
        }
        let mlkemPublicKey = clientShare.extracting(
            0..<MLKEM768.PublicKey.byteCount
        )
        var serverShare = ContiguousArray<UInt8>(
            repeating: 0,
            count: namedGroup.serverShareByteCount
        )
        let byteCount: SecretByteCount
        do {
            byteCount = try SecretByteCount(namedGroup.sharedSecretByteCount)
        } catch let error {
            throw .secretMemory(error)
        }
        let entropySource: any EntropySource = copy entropy
        var combinedSecret = SecretBytes(byteCount: byteCount) { _ in }
        do {
            try Self.deriveX25519Secret(
                clientShare.extracting(MLKEM768.PublicKey.byteCount..<clientShare.count),
                using: x25519PrivateKey,
                into: &combinedSecret
            )
        } catch let error {
            throw .crypto(error)
        }
        do {
            try combinedSecret.withMutableBorrowedBytes {
                output throws(KEMError) in
                var serverShareSpan = serverShare.mutableSpan
                var ciphertextOutput = serverShareSpan._mutatingExtracting(
                    0..<MLKEM768.Encapsulation.byteCount
                )
                var mlkemOutput = output._mutatingExtracting(
                    0..<MLKEM768.SharedSecret.byteCount
                )
                try Self.encapsulate(
                    toEncodedPublicKey: mlkemPublicKey,
                    using: entropySource,
                    into: &ciphertextOutput,
                    sharedSecret: &mlkemOutput
                )
            }
        } catch let error {
            throw .kem(error)
        }
        do {
            var serverShareSpan = serverShare.mutableSpan
            var x25519Output = serverShareSpan._mutatingExtracting(
                MLKEM768.Encapsulation.byteCount..<namedGroup.serverShareByteCount
            )
            try x25519PrivateKey.publicKey(into: &x25519Output)
        } catch let error {
            throw .crypto(error)
        }
        return TLS13ServerKeyExchangeResult(
            serverShare: OwnedBytes(consuming: serverShare),
            sharedSecret: combinedSecret
        )
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

    private static func encapsulate(
        toEncodedPublicKey publicKey: Span<UInt8>,
        using entropy: borrowing any EntropySource,
        into encapsulation: inout MutableSpan<UInt8>,
        sharedSecret: inout MutableSpan<UInt8>
    ) throws(KEMError) {
        try MLKEM768.encapsulate(
            toEncodedPublicKey: publicKey,
            using: entropy,
            into: &encapsulation,
            sharedSecret: &sharedSecret
        )
    }

}
