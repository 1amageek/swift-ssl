import SwiftSSLCore

public enum SHAKE128: ExtendableOutputFunction {
  public typealias Context = SHAKE128Context

  public static func makeContext() -> SHAKE128Context { SHAKE128Context() }

  public static func hash(
    _ input: Span<UInt8>,
    outputByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard outputByteCount >= 0, output.count == outputByteCount else {
      throw .invalidOutputLength(expected: outputByteCount, actual: output.count)
    }
    var context = SHAKE128Context()
    try context.update(input)
    try context.finalize(into: &output)
  }
}

public enum SHAKE256: ExtendableOutputFunction {
  public typealias Context = SHAKE256Context

  public static func makeContext() -> SHAKE256Context { SHAKE256Context() }

  public static func hash(
    _ input: Span<UInt8>,
    outputByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard outputByteCount >= 0, output.count == outputByteCount else {
      throw .invalidOutputLength(expected: outputByteCount, actual: output.count)
    }
    var context = SHAKE256Context()
    try context.update(input)
    try context.finalize(into: &output)
  }
}
