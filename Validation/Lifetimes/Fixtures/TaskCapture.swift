public func invalidTaskCapture(_ secret: borrowing SecretBytes) {
    secret.withBorrowedBytes { bytes in
        Task {
            _ = bytes[0]
        }
    }
}
