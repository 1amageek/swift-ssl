public protocol MonotonicClock: Sendable {
    func now() throws(ClockError) -> MonotonicInstant
}
