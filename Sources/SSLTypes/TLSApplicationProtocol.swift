/// An owned ALPN protocol identifier.
///
/// The vocabulary layer stores only bytes and does not interpret an ALPN name.
/// Protocol-specific validation and wire framing remain in the owning session.
public struct TLSApplicationProtocol: Sendable, Hashable {
    private let bytes: ContiguousArray<UInt8>

    public init(bytes: consuming ContiguousArray<UInt8>) throws(TLSVocabularyError) {
        guard !bytes.isEmpty, bytes.count <= UInt8.max else {
            throw .invalidLength(actual: bytes.count)
        }
        self.bytes = consume bytes
    }

    public var byteCount: Int { bytes.count }

    public borrowing func withBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(bytes.span)
    }
}
