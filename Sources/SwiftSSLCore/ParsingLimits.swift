public struct ParsingLimits: Sendable, Hashable {
    public let maximumInputBytes: Int
    public let maximumNestingDepth: Int
    public let maximumElementCount: Int
    public let maximumExtensionCount: Int
    public let maximumOIDBytes: Int
    public let maximumStringBytes: Int

    public init(
        maximumInputBytes: Int,
        maximumNestingDepth: Int,
        maximumElementCount: Int,
        maximumExtensionCount: Int,
        maximumOIDBytes: Int,
        maximumStringBytes: Int
    ) throws(ResourceLimitError) {
        try Self.requirePositive(maximumInputBytes, name: "maximumInputBytes")
        try Self.requirePositive(maximumNestingDepth, name: "maximumNestingDepth")
        try Self.requirePositive(maximumElementCount, name: "maximumElementCount")
        try Self.requirePositive(maximumExtensionCount, name: "maximumExtensionCount")
        try Self.requirePositive(maximumOIDBytes, name: "maximumOIDBytes")
        try Self.requirePositive(maximumStringBytes, name: "maximumStringBytes")

        self.maximumInputBytes = maximumInputBytes
        self.maximumNestingDepth = maximumNestingDepth
        self.maximumElementCount = maximumElementCount
        self.maximumExtensionCount = maximumExtensionCount
        self.maximumOIDBytes = maximumOIDBytes
        self.maximumStringBytes = maximumStringBytes
    }

    private static func requirePositive(
        _ value: Int,
        name: String
    ) throws(ResourceLimitError) {
        guard value > 0 else {
            throw .invalidLimit(name: name, value: value)
        }
    }
}
