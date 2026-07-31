public protocol HashFunction: Sendable {
  associatedtype Context: ~Copyable & HashContext

  static var digestByteCount: Int { get }

  static func makeContext() -> Context

  /// Writes exactly `digestByteCount` bytes into an equally sized output.
  ///
  /// Implementations must reject any other output size before modifying it.
  static func hash(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)
}

public extension HashFunction {
  static func hash(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    var context = makeContext()
    try context.update(input)
    try context.finalize(into: &output)
  }
}
