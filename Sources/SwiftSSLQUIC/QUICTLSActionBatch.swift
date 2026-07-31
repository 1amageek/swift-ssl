import SwiftSSLCore
import SwiftSSLTLS

public struct QUICTLSActionBatch: Sendable {
    public let bytes: OwnedBytes
    public let actions: ContiguousArray<QUICTLSAction>

    package init(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<QUICTLSAction>
    ) throws(ByteError) {
        try TLSActionBatchValidator.validate(bytes: bytes, actions: actions)
        self.bytes = bytes
        self.actions = actions
    }
}
