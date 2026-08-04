/// An owned server-name indication value.
///
/// Name syntax, DNS canonicalization, and identity policy belong to the
/// certificate/session layer. This type deliberately remains an opaque byte
/// vocabulary value.
public struct TLSServerName: Sendable, Hashable {
    private let bytes: ContiguousArray<UInt8>

    public init(bytes: consuming ContiguousArray<UInt8>) throws(TLSVocabularyError) {
        guard !bytes.isEmpty, bytes.count <= UInt16.max else {
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
