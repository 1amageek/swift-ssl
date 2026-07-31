public enum ResourceLimitError: Error, Sendable, Equatable {
    case invalidLimit(name: String, value: Int)
    case unbalancedNesting
    case inputBytes(limit: Int, actual: Int)
    case nestingDepth(limit: Int)
    case elementCount(limit: Int)
    case extensionCount(limit: Int)
    case oidBytes(limit: Int, actual: Int)
    case stringBytes(limit: Int, actual: Int)
}
