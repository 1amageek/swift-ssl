public func invalidEscapingBorrow(
    _ secret: borrowing SecretBytes
) -> Span<UInt8> {
    secret.withBorrowedBytes { bytes in bytes }
}
