import SSLCore

public enum TLS13ResumptionError: Error, Sendable, Equatable {
    case invalidTicketLength(actual: Int)
    case invalidNonceLength(actual: Int)
    case invalidSecretLength(expected: Int, actual: Int)
    case invalidLifetime
    case issuedInFuture
    case expired
    case replayDetected
    case cryptographicFailure
}
