import SSLCore

public struct P256SharedSecret: ~Copyable, Sendable {
  public static let byteCount = 32
  private let storage: SecretBytes

  init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }
}
