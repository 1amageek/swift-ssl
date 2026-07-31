public func invalidDoubleConsume(_ secret: consuming SecretBytes) {
    let first = secret
    let second = secret
    first.withBorrowedBytes { _ in }
    second.withBorrowedBytes { _ in }
}
