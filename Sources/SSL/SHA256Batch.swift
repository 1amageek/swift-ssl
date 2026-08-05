import SSLCrypto

extension SHA256: BatchHashFunction {
  public static var preferredBatchWidth: Int {
    SSLCrypto.SHA256.preferredBatchWidth
  }

  public static func hashBatch(
    _ inputStorage: Span<UInt8>,
    inputs: Span<HashBatchInput>,
    into output: inout MutableSpan<UInt8>
  ) throws(BatchHashError) {
    do {
      try SSLCrypto.SHA256.hashBatch(
        inputStorage,
        inputs: inputs,
        into: &output
      )
    } catch {
      throw BatchHashError(error)
    }
  }
}
