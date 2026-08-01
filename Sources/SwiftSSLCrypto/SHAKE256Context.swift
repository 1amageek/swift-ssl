import SwiftSSLCore

public struct SHAKE256Context: ~Copyable, ExtendableOutputFunctionContext {
  private var core: KeccakCore

  public init() {
    core = KeccakCore(rateByteCount: 136, domainSeparator: 0x1F)
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

  package mutating func squeeze(into output: inout MutableSpan<UInt8>) {
    core.squeeze(into: &output)
  }

  package mutating func erase() {
    core.erase()
  }

  public borrowing func clone() -> SHAKE256Context {
    SHAKE256Context(core: core.clone())
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    core.finalize(into: &output)
  }
}
