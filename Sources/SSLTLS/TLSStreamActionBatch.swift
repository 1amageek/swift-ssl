import SSLCore

public struct TLSStreamActionBatch: Sendable {
    public let bytes: OwnedBytes
    public let actions: ContiguousArray<TLSStreamAction>

    package init(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<TLSStreamAction>
    ) throws(ByteError) {
        try TLSActionBatchValidator.validate(bytes: bytes, actions: actions)
        self.bytes = bytes
        self.actions = actions
    }
}
