public struct ParsingBudget: Sendable {
    public let limits: ParsingLimits

    private var currentDepth: Int
    private var elementCount: Int
    private var extensionCount: Int

    public init(limits: ParsingLimits, inputByteCount: Int) throws(ResourceLimitError) {
        guard inputByteCount <= limits.maximumInputBytes else {
            throw .inputBytes(limit: limits.maximumInputBytes, actual: inputByteCount)
        }
        guard inputByteCount >= 0 else {
            throw .invalidLimit(name: "inputByteCount", value: inputByteCount)
        }

        self.limits = limits
        currentDepth = 0
        elementCount = 0
        extensionCount = 0
    }

    public mutating func consumeElement() throws(ResourceLimitError) {
        let (newCount, overflow) = elementCount.addingReportingOverflow(1)
        guard !overflow, newCount <= limits.maximumElementCount else {
            throw .elementCount(limit: limits.maximumElementCount)
        }
        elementCount = newCount
    }

    public mutating func enterContainer() throws(ResourceLimitError) {
        let (newDepth, overflow) = currentDepth.addingReportingOverflow(1)
        guard !overflow, newDepth <= limits.maximumNestingDepth else {
            throw .nestingDepth(limit: limits.maximumNestingDepth)
        }
        currentDepth = newDepth
    }

    public mutating func leaveContainer() throws(ResourceLimitError) {
        guard currentDepth > 0 else {
            throw .unbalancedNesting
        }
        currentDepth -= 1
    }

    public mutating func consumeExtension() throws(ResourceLimitError) {
        let (newCount, overflow) = extensionCount.addingReportingOverflow(1)
        guard !overflow, newCount <= limits.maximumExtensionCount else {
            throw .extensionCount(limit: limits.maximumExtensionCount)
        }
        extensionCount = newCount
    }

    public func requireOIDByteCount(_ byteCount: Int) throws(ResourceLimitError) {
        guard byteCount >= 0 else {
            throw .invalidLimit(name: "oidByteCount", value: byteCount)
        }
        guard byteCount <= limits.maximumOIDBytes else {
            throw .oidBytes(limit: limits.maximumOIDBytes, actual: byteCount)
        }
    }

    public func requireStringByteCount(_ byteCount: Int) throws(ResourceLimitError) {
        guard byteCount >= 0 else {
            throw .invalidLimit(name: "stringByteCount", value: byteCount)
        }
        guard byteCount <= limits.maximumStringBytes else {
            throw .stringBytes(limit: limits.maximumStringBytes, actual: byteCount)
        }
    }
}
