
public protocol BatchHashFunction: HashFunction {
  /// Preferred number of independent messages for one optimized group.
  static var preferredBatchWidth: Int { get }

  /// Hashes every range in order and writes packed fixed-size digests.
  ///
  /// Digest `i` occupies
  /// `i * digestByteCount ..< (i + 1) * digestByteCount`. All ranges and the
  /// complete output are validated before output mutation. Input storage and
  /// output storage must not overlap.
  static func hashBatch(
    _ inputStorage: Span<UInt8>,
    inputs: Span<HashBatchInput>,
    into output: inout MutableSpan<UInt8>
  ) throws(BatchHashError)
}
