import SSLCore
import SSLCrypto

public struct SHAKE128Context: ~Copyable {
  private var implementation: SSLCrypto.SHAKE128Context

  public init() { implementation = SSLCrypto.SHAKE128Context() }

  private init(implementation: consuming SSLCrypto.SHAKE128Context) {
    self.implementation = implementation
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    do { try implementation.update(input) } catch { throw CryptoInputError(error) }
  }

  public borrowing func clone() -> SHAKE128Context {
    SHAKE128Context(implementation: implementation.clone())
  }

  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
  }
}

public struct SHAKE256Context: ~Copyable {
  private var implementation: SSLCrypto.SHAKE256Context

  public init() { implementation = SSLCrypto.SHAKE256Context() }

  private init(implementation: consuming SSLCrypto.SHAKE256Context) {
    self.implementation = implementation
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    do { try implementation.update(input) } catch { throw CryptoInputError(error) }
  }

  public borrowing func clone() -> SHAKE256Context {
    SHAKE256Context(implementation: implementation.clone())
  }

  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
  }
}

public enum SHAKE128 {
  public static func makeContext() -> SHAKE128Context { SHAKE128Context() }

  public static func hash(
    _ input: Span<UInt8>,
    outputByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do {
      try SSLCrypto.SHAKE128.hash(input, outputByteCount: outputByteCount, into: &output)
    } catch {
      throw CryptoInputError(error)
    }
  }
}

public enum SHAKE256 {
  public static func makeContext() -> SHAKE256Context { SHAKE256Context() }

  public static func hash(
    _ input: Span<UInt8>,
    outputByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do {
      try SSLCrypto.SHAKE256.hash(input, outputByteCount: outputByteCount, into: &output)
    } catch {
      throw CryptoInputError(error)
    }
  }
}
