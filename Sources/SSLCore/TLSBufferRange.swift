/// A validated range into an owner-owned transport buffer.
///
/// The range is a descriptor only. It does not retain storage and can be used
/// only while the owner is borrowed. This keeps the public contract explicit
/// about ownership instead of returning an escaping pointer or slice.
public struct TLSBufferRange: Sendable, Hashable {
    public let offset: Int
    public let count: Int

    public init(offset: Int, count: Int) throws(ByteError) {
        let range = try ByteRange(offset: offset, count: count)
        self.offset = range.offset
        self.count = range.count
    }

    public var endOffset: Int { offset + count }

    public func byteRange() throws(ByteError) -> ByteRange {
        try ByteRange(offset: offset, count: count)
    }
}
