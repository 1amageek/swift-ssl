import SwiftSSLCore

public protocol ExtendableOutputFunction: Sendable {
  associatedtype Context: ~Copyable & ExtendableOutputFunctionContext

  static func makeContext() -> Context
  static func hash(
    _ input: Span<UInt8>,
    outputByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)
}

public protocol ExtendableOutputFunctionContext: ~Copyable {
  mutating func update(_ input: Span<UInt8>) throws(CryptoInputError)
  borrowing func clone() -> Self
  consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError)
}
