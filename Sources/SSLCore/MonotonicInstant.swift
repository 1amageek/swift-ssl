public struct MonotonicInstant: Sendable, Hashable {
    public let clockIdentifier: UInt64
    public let ticks: UInt64
    public let ticksPerSecond: UInt64

    public init(
        clockIdentifier: UInt64,
        ticks: UInt64,
        ticksPerSecond: UInt64
    ) throws(ClockError) {
        guard ticksPerSecond > 0 else {
            throw .backendFailure(code: 0)
        }
        self.clockIdentifier = clockIdentifier
        self.ticks = ticks
        self.ticksPerSecond = ticksPerSecond
    }

    public func tickDistance(
        since earlier: MonotonicInstant
    ) throws(ClockError) -> UInt64 {
        guard clockIdentifier == earlier.clockIdentifier else {
            throw .clockDomainMismatch(
                expected: clockIdentifier,
                actual: earlier.clockIdentifier
            )
        }
        guard ticksPerSecond == earlier.ticksPerSecond else {
            throw .clockDomainMismatch(
                expected: ticksPerSecond,
                actual: earlier.ticksPerSecond
            )
        }
        guard ticks >= earlier.ticks else {
            throw .movedBackwards
        }
        return ticks - earlier.ticks
    }
}
