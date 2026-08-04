// Bytes.swift
// A Foundation-free byte container that replaces `Data` in the Embedded core.
// Owns storage as `[UInt8]`; exposes borrowed views as `Span<UInt8>` / `RawSpan`.

/// A `Sendable`/`Hashable` value over owned `[UInt8]`.
///
/// `Bytes` is the Embedded-clean replacement for Foundation's `Data` throughout
/// the P2P/QUIC/TLS stack. Borrowed views are produced on demand via
/// `borrowing get` + `@_lifetime(borrow self)` (A1); a `Span` is **never stored**.
public struct Bytes: Sendable, Hashable {
    @usableFromInline var storage: [UInt8]

    // MARK: Counts

    /// The number of bytes held.
    @inlinable public var count: Int { storage.count }

    /// Whether the container holds zero bytes.
    @inlinable public var isEmpty: Bool { storage.isEmpty }

    // MARK: Borrowed views (EXACT proven form, A1)

    /// A borrowed, read-only typed view over the storage.
    public var span: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { storage.span }
    }

    /// A borrowed, read-only raw view over the storage.
    public var rawSpan: RawSpan {                 // note: storage.span.bytes, NOT storage.bytes
        @_lifetime(borrow self)
        borrowing get { storage.span.bytes }
    }

    // MARK: Element access (traps on programmer error only — matches Array)

    /// Element access by index. Traps only on programmer error (out-of-bounds),
    /// matching `Array`; untrusted wire data must go through ``ByteReader``.
    @inlinable public subscript(_ index: Int) -> UInt8 { storage[index] }

    // MARK: Inits

    /// Creates an empty container.
    @inlinable public init() {
        self.storage = []
    }

    /// Creates a container by taking ownership of an existing array.
    @inlinable public init(_ array: [UInt8]) {
        self.storage = array
    }

    /// Creates a container by copying any byte sequence.
    @inlinable public init(_ sequence: some Sequence<UInt8>) {
        self.storage = Array(sequence)
    }

    /// Creates a container by copying a borrowed typed view (A2).
    public init(_ span: Span<UInt8>) {
        var array = [UInt8]()
        array.reserveCapacity(span.count)
        for index in 0..<span.count {
            array.append(span[index])
        }
        self.storage = array
    }

    /// Creates a container by copying a raw view via `unsafeLoad` (A2).
    public init(_ rawSpan: RawSpan) {
        var array = [UInt8]()
        let count = rawSpan.byteCount
        array.reserveCapacity(count)
        for index in 0..<count {
            array.append(rawSpan.unsafeLoad(fromByteOffset: index, as: UInt8.self))
        }
        self.storage = array
    }

    // MARK: Owned export

    /// Returns the owned storage as a fresh array copy, at an API boundary.
    @inlinable public func toArray() -> [UInt8] {
        storage
    }

    // MARK: Bounds-checked sub-slicing (typed errors, NEVER traps on bad length)

    /// Returns a copy of the bytes in `range` as a new `Bytes`.
    ///
    /// - Throws: ``ByteError/indexOutOfRange`` if `lowerBound < 0`,
    ///   `upperBound > count`, or the range is inverted.
    public func slice(_ range: Range<Int>) throws(ByteError) -> Bytes {
        guard range.lowerBound >= 0,
              range.upperBound <= storage.count,
              range.lowerBound <= range.upperBound else {
            throw ByteError.indexOutOfRange
        }
        var array = [UInt8]()
        array.reserveCapacity(range.count)
        for index in range {
            array.append(storage[index])
        }
        return Bytes(array)
    }

    /// Returns a copy of `count` bytes starting at `offset`.
    ///
    /// - Throws: ``ByteError/indexOutOfRange`` if `offset < 0`, `count < 0`, or
    ///   `offset + count > count`.
    public func slice(at offset: Int, count: Int) throws(ByteError) -> Bytes {
        guard offset >= 0, count >= 0 else {
            throw ByteError.indexOutOfRange
        }
        return try slice(offset..<(offset + count))
    }

    // MARK: Append / concat

    /// Returns the concatenation of two byte containers.
    public static func + (lhs: Bytes, rhs: Bytes) -> Bytes {
        var array = lhs.storage
        array.append(contentsOf: rhs.storage)
        return Bytes(array)
    }

    /// Appends the contents of another container.
    public mutating func append(_ other: Bytes) {
        storage.append(contentsOf: other.storage)
    }

    /// Appends any byte sequence.
    public mutating func append(contentsOf seq: some Sequence<UInt8>) {
        storage.append(contentsOf: seq)
    }
}
