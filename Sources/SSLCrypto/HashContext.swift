import SSLCore

public protocol HashContext: ~Copyable {
  static var digestByteCount: Int { get }

  mutating func update(_ input: Span<UInt8>) throws(CryptoInputError)

  /// Returns an independent snapshot of the current hash state.
  ///
  /// Subsequent mutation of either context must not affect the other.
  borrowing func clone() -> Self

  /// Writes exactly `digestByteCount` bytes into an equally sized output.
  ///
  /// Implementations must reject any other output size before modifying it.
  consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)
}
