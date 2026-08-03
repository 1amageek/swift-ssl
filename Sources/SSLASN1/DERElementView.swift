public struct DERElementView: ~Escapable {
    public let tag: DERTag
    public let encodedOffset: Int
    public let headerByteCount: Int
    public let encodedBytes: Span<UInt8>
    public let contentBytes: Span<UInt8>

    @_lifetime(copy encodedBytes)
    init(
        tag: DERTag,
        encodedOffset: Int,
        headerByteCount: Int,
        encodedBytes: Span<UInt8>
    ) {
        self.tag = tag
        self.encodedOffset = encodedOffset
        self.headerByteCount = headerByteCount
        self.encodedBytes = encodedBytes
        contentBytes = encodedBytes.extracting(droppingFirst: headerByteCount)
    }
}
