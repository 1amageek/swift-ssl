public struct OCSPValidationPolicy: Sendable, Hashable {
    public let requireNextUpdate: Bool
    public let maximumAgeWithoutNextUpdateSeconds: Int64
    public let maximumClockSkewSeconds: Int64

    public init(
        requireNextUpdate: Bool = true,
        maximumAgeWithoutNextUpdateSeconds: Int64 = 86_400,
        maximumClockSkewSeconds: Int64 = 300
    ) {
        precondition(maximumAgeWithoutNextUpdateSeconds >= 0)
        precondition(maximumClockSkewSeconds >= 0)
        self.requireNextUpdate = requireNextUpdate
        self.maximumAgeWithoutNextUpdateSeconds =
            maximumAgeWithoutNextUpdateSeconds
        self.maximumClockSkewSeconds = maximumClockSkewSeconds
    }
}
