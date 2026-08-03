public struct VerificationInstant: Sendable, Hashable, Comparable {
    public let secondsSinceUnixEpoch: Int64
    public let nanoseconds: UInt32

    public init(
        secondsSinceUnixEpoch: Int64,
        nanoseconds: UInt32
    ) throws(ClockError) {
        guard nanoseconds < 1_000_000_000 else {
            throw .invalidNanoseconds(nanoseconds)
        }
        self.secondsSinceUnixEpoch = secondsSinceUnixEpoch
        self.nanoseconds = nanoseconds
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.secondsSinceUnixEpoch != rhs.secondsSinceUnixEpoch {
            return lhs.secondsSinceUnixEpoch < rhs.secondsSinceUnixEpoch
        }
        return lhs.nanoseconds < rhs.nanoseconds
    }
}
