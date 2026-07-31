import SwiftSSLCore

public enum KEMError: Error, Sendable, Equatable {
    case entropy(EntropyError)
    case invalidPublicKeyLength(expected: Int, actual: Int)
    case invalidPublicKeyEncoding
    case invalidPrivateKeyLength(expected: Int, actual: Int)
    case invalidPrivateKeyEncoding
    case invalidEncapsulationLength(expected: Int, actual: Int)
}
