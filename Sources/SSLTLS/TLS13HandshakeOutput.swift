import SSLCore

/// One owned output batch from a TLS 1.3 handshake step.
///
/// The byte backing is owned once and actions contain only checked ranges into
/// that backing. The owner remains valid until the output is consumed.
public struct TLS13HandshakeOutput: Sendable {
    public let bytes: OwnedBytes
    public let actions: ContiguousArray<TLSStreamAction>

    package init(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<TLSStreamAction>
    ) throws(TLS13HandshakeEngineError) {
        do {
            try TLSActionBatchValidator.validate(bytes: bytes, actions: actions)
        } catch let error {
            throw .output(error)
        }
        self.bytes = bytes
        self.actions = actions
    }
}
