/// Failure raised by a caller-owned output sink.
public enum TLSOutputSinkError: Error, Sendable, Equatable {
    case insufficientCapacity(required: Int, available: Int)
    case invalidRange(ByteError)
}

/// A caller-owned destination for encoded TLS output.
///
/// Implementations choose the storage and allocation policy. The TLS mechanism
/// writes through a scoped span and reports capacity failure; it never silently
/// reallocates or truncates caller storage.
public protocol TLSOutputSink: ~Copyable, Sendable {
    var remainingCapacity: Int { get }

    mutating func write(
        _ bytes: Span<UInt8>
    ) throws(TLSOutputSinkError)
}
