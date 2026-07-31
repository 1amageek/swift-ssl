import SwiftSSLCrypto

public enum TLS13KeyScheduleError: Error, Sendable, Equatable {
    case invalidPreSharedKeyLength(actual: Int)
    case invalidECDHESecretLength(actual: Int)
    case invalidTranscriptHashLength(expected: Int, actual: Int)
    case invalidOutputLength(actual: Int)
    case hkdfFailure(HKDFError)
    case cryptographicFailure
    case invalidSecretMemory
}
