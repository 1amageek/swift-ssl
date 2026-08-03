import SSLCrypto

public struct SHA256Context: ~Copyable, HashContext {
  public static let digestByteCount = 32

  private var implementation: SSLCrypto.SHA256Context

  public init() {
    implementation = SSLCrypto.SHA256Context()
  }

  private init(
    implementation: consuming SSLCrypto.SHA256Context
  ) {
    self.implementation = implementation
  }

  public mutating func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError) {
    do {
      try implementation.update(input)
    } catch {
      throw CryptoInputError(error)
    }
  }

  public borrowing func clone() -> SHA256Context {
    SHA256Context(implementation: implementation.clone())
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do {
      try implementation.finalize(into: &output)
    } catch {
      throw CryptoInputError(error)
    }
  }
}
