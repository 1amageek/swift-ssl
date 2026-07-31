public struct ByteRange: Sendable, Hashable {
    public let offset: Int
    public let count: Int

    public init(offset: Int, count: Int) throws(ByteError) {
        guard offset >= 0 else {
            throw .outOfBounds(offset: offset, requested: count, available: 0)
        }
        guard count >= 0 else {
            throw .negativeCount(count)
        }

        let (_, overflow) = offset.addingReportingOverflow(count)
        guard !overflow else {
            throw .offsetOverflow(offset: offset, count: count)
        }

        self.offset = offset
        self.count = count
    }

    public var endOffset: Int {
        offset + count
    }
}
