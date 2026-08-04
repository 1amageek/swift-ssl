import SSLCore

public struct SHA3_512Context: ~Copyable, HashContext, Sendable {
  public static let digestByteCount = 64

  private var core: KeccakCore

  public init() {
    core = KeccakCore(rateByteCount: 72, domainSeparator: 0x06)
  }

  private init(core: consuming KeccakCore) {
    self.core = core
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try core.update(input)
  }

  package mutating func update(byte: UInt8) throws(CryptoInputError) {
    try core.update(byte: byte)
  }

  public borrowing func clone() -> SHA3_512Context {
    SHA3_512Context(core: core.clone())
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try finalizeInPlace(into: &output)
  }

  package mutating func finalizeInPlace(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    core.finalize(into: &output)
  }

  package mutating func eraseSensitiveState() {
    core.erase()
  }
}
