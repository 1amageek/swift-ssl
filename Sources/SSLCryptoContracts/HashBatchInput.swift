public struct HashBatchInput: Sendable, Equatable {
  public let offset: Int
  public let byteCount: Int

  public init(offset: Int, byteCount: Int) {
    self.offset = offset
    self.byteCount = byteCount
  }
}
