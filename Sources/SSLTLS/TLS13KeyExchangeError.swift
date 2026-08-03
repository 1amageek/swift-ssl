import SSLCore
import SSLCrypto

public enum TLS13KeyExchangeError: Error, Sendable, Equatable {
    case invalidState
    case unexpectedNamedGroup(expected: TLS13NamedGroup, actual: TLS13NamedGroup)
    case invalidShareLength(expected: Int, actual: Int)
    case kem(KEMError)
    case crypto(CryptoInputError)
    case p256KeyGeneration(P256KeyGenerationError)
    case x25519KeyGeneration(X25519KeyGenerationError)
    case secretMemory(SecretMemoryError)
}
