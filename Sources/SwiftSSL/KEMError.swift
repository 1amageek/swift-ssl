import SwiftSSLCrypto

public enum KEMError: Error, Sendable, Equatable {
    case entropy(EntropyError)
    case primitiveFailure(CryptoInputError)
    case secretMemory(SecretMemoryError)
    case invalidPublicKeyLength(expected: Int, actual: Int)
    case invalidPublicKeyEncoding
    case invalidPrivateKeyLength(expected: Int, actual: Int)
    case invalidPrivateKeyEncoding
    case invalidEncapsulationLength(expected: Int, actual: Int)
    case invalidSharedSecretLength(expected: Int, actual: Int)

    init(_ error: SwiftSSLCrypto.KEMError) {
        switch error {
        case .entropy(let value):
            self = .entropy(value)
        case .primitiveFailure(let value):
            self = .primitiveFailure(CryptoInputError(value))
        case .secretMemory(let value):
            self = .secretMemory(SecretMemoryError(value))
        case .invalidPublicKeyLength(let expected, let actual):
            self = .invalidPublicKeyLength(expected: expected, actual: actual)
        case .invalidPublicKeyEncoding:
            self = .invalidPublicKeyEncoding
        case .invalidPrivateKeyLength(let expected, let actual):
            self = .invalidPrivateKeyLength(expected: expected, actual: actual)
        case .invalidPrivateKeyEncoding:
            self = .invalidPrivateKeyEncoding
        case .invalidEncapsulationLength(let expected, let actual):
            self = .invalidEncapsulationLength(expected: expected, actual: actual)
        case .invalidSharedSecretLength(let expected, let actual):
            self = .invalidSharedSecretLength(expected: expected, actual: actual)
        }
    }
}
