import SSLCore

package enum TLSActionBatchValidator {
    package static func validate<Action: TLSBatchAction>(
        bytes: borrowing OwnedBytes,
        actions: borrowing ContiguousArray<Action>
    ) throws(ByteError) {
        var index = 0
        while index < actions.count {
            if let range = actions[index].referencedByteRange {
                guard bytes.contains(range) else {
                    throw .outOfBounds(
                        offset: range.offset,
                        requested: range.count,
                        available: Swift.max(0, bytes.count - range.offset)
                    )
                }
            }
            index += 1
        }
    }
}
