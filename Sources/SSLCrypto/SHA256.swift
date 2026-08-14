import SSLCore

public enum SHA256: HashFunction {
  public typealias Context = SHA256Context

  public static let digestByteCount = SHA256Context.digestByteCount

  public static func makeContext() -> SHA256Context {
    SHA256Context()
  }

  @inlinable
  @inline(__always)
  public static func hash(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try SHA256Context.hashOneShot(input, into: &output)
  }
}
