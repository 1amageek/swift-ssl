import SSLCore

public struct SHA3_256Context: ~Copyable, HashContext {
  public static let digestByteCount = 32

  private var core: KeccakCore

  public init() {
    core = KeccakCore(rateByteCount: 136, domainSeparator: 0x06)
  }

  private init(core: consuming KeccakCore) {
    self.core = core
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try core.update(input)
  }

  public borrowing func clone() -> SHA3_256Context {
    SHA3_256Context(core: core.clone())
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    core.finalize(into: &output)
  }
}
