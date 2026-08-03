public struct CertificateTransparencyPolicy: Sendable, Hashable {
    public let minimumValidSCTCount: Int
    public let minimumDistinctOperatorCount: Int
    public let maximumClockSkewSeconds: Int64

    public init(
        minimumValidSCTCount: Int = 2,
        minimumDistinctOperatorCount: Int = 2,
        maximumClockSkewSeconds: Int64 = 300
    ) {
        precondition(minimumValidSCTCount > 0)
        precondition(minimumDistinctOperatorCount > 0)
        precondition(maximumClockSkewSeconds >= 0)
        self.minimumValidSCTCount = minimumValidSCTCount
        self.minimumDistinctOperatorCount = minimumDistinctOperatorCount
        self.maximumClockSkewSeconds = maximumClockSkewSeconds
    }
}
