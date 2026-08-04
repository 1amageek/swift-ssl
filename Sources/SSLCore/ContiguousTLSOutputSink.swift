/// A bounded output sink backed by an owning `OwnedBytes` value.
///
/// This is useful for adapters that need a deterministic capacity contract. It
/// intentionally copies only at the explicit output boundary.
public struct ContiguousTLSOutputSink: TLSOutputSink, ~Copyable, Sendable {
    private var builder: ByteBuilder

    public init(maximumByteCount: Int, minimumCapacity: Int = 0) throws(ByteError) {
        builder = try ByteBuilder(
            maximumByteCount: maximumByteCount,
            minimumCapacity: minimumCapacity
        )
    }

    public var remainingCapacity: Int { builder.remainingCapacity }

    public mutating func write(
        _ bytes: Span<UInt8>
    ) throws(TLSOutputSinkError) {
        do {
            try builder.append(bytes)
        } catch let error {
            switch error {
            case .capacityExceeded:
                throw .insufficientCapacity(
                    required: bytes.count,
                    available: builder.remainingCapacity
                )
            default:
                throw .invalidRange(error)
            }
        }
    }

    public consuming func finish() -> OwnedBytes {
        builder.finish()
    }
}
