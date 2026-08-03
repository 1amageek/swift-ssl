public protocol WallClock: Sendable {
    func now() throws(ClockError) -> VerificationInstant
}
