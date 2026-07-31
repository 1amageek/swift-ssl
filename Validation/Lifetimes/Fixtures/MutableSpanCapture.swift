public func invalidMutableSpanCapture(
    _ byteCount: SecretByteCount
) -> () -> UInt8 {
    var escaped: (() -> UInt8)?
    let secret = SecretBytes(byteCount: byteCount) { destination in
        escaped = { destination[0] }
    }
    secret.withBorrowedBytes { _ in }
    return escaped!
}
