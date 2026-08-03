import SSLCrypto

public enum SHA256: HashFunction {
  public typealias Context = SHA256Context

  public static let digestByteCount = SHA256Context.digestByteCount

  public static func makeContext() -> SHA256Context {
    SHA256Context()
  }

  public static func hash(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do {
      try SSLCrypto.SHA256.hash(input, into: &output)
    } catch {
      throw CryptoInputError(error)
    }
  }
}
