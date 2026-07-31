import SwiftSSLCrypto

public enum QUICInitialSecretsError: Error, Sendable, Equatable {
    case invalidDestinationConnectionIDLength(actual: Int)
    case hkdfFailure(HKDFError)
    case secretMemoryFailure
}
