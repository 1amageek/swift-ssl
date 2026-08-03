import SSLCore

public struct DTLSActionBatch: Sendable {
    public let bytes: OwnedBytes
    public let actions: ContiguousArray<DTLSAction>

    package init(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<DTLSAction>
    ) throws(ByteError) {
        try TLSActionBatchValidator.validate(bytes: bytes, actions: actions)
        self.bytes = bytes
        self.actions = actions
    }
}
