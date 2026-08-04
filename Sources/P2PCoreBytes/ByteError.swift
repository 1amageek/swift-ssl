// ByteError.swift
// Typed errors for byte reading/writing. Embedded-clean: no Foundation, no `any`.

/// Errors raised by ``ByteReader`` and ``ByteWriter`` on malformed or out-of-range
/// input. Every parse failure is a distinct typed case propagated to the caller;
/// there is no `try?` and no silent fallback. Typed `throws(ByteError)` avoids the
/// Embedded untyped-throws warning and gives callers exhaustive `catch`.
public enum ByteError: Error, Equatable, Sendable {
    /// A read requested more bytes than remain in the buffer.
    case insufficientBytes(requested: Int, available: Int)

    /// A declared vector length exceeded the bytes that remain.
    case lengthOverflow(declared: Int, available: Int)

    /// A varint encode exceeded the QUIC 62-bit varint range (`2^62 - 1`).
    case invalidVarint

    /// A write value or length exceeded the width of its fixed-size prefix.
    case lengthOutOfRange

    /// A slice/skip index or count was out of bounds.
    case indexOutOfRange
}
