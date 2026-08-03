public enum ClockError: Error, Sendable, Equatable {
    case unavailable
    case invalidNanoseconds(UInt32)
    case backendValueOutOfRange
    case tickOverflow
    case movedBackwards
    case clockDomainMismatch(expected: UInt64, actual: UInt64)
    case backendFailure(code: Int)
}
