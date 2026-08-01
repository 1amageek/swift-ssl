import SwiftSSLCore

enum MLKEMSecretFactory {
  static func withRandom32ByteBlock<Result: ~Copyable>(
    using entropy: consuming any EntropySource,
    _ body: (Span<UInt8>) throws(KEMError) -> Result
  ) throws(KEMError) -> Result {
    var bytes = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - bytes owns exactly 32 initialized UInt8 values for this synchronous closure.
    // - UInt8 has stride and alignment one; the mutable and immutable spans cover
    //   precisely the same fixed stack storage without rebinding it.
    // - EntropySource.fill and body borrow their spans only for their calls; neither
    //   pointer nor span escapes or crosses a Sendable boundary.
    // - The mutable borrow ends before the immutable borrow begins.
    // - Volatile erasure runs on success and failure before the stack storage dies.
    return try withUnsafeMutableBytes(of: &bytes) {
      rawBytes throws(KEMError) -> Result in
      let rawPointer = rawBytes.baseAddress!
      defer {
        SecureWipe.erase(rawPointer, byteCount: rawBytes.count)
      }

      let bytePointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var destination = MutableSpan(_unsafeStart: bytePointer, count: rawBytes.count)
      switch fillResult(&destination, using: entropy) {
      case .success:
        break
      case .failure(let error):
        throw .entropy(error)
      }

      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(bytePointer),
        count: rawBytes.count
      )
      return try body(Span(_unsafeElements: buffer))
    }
  }

  private static func fillResult(
    _ destination: inout MutableSpan<UInt8>,
    using entropy: borrowing any EntropySource
  ) -> Result<Void, EntropyError> {
    do {
      try entropy.fill(&destination)
      return .success(())
    } catch {
      return .failure(error)
    }
  }

  static func make(
    byteCount: Int,
    initializer: borrowing (inout MutableSpan<UInt8>) throws(KEMError) -> Void
  ) throws(KEMError) -> SecretBytes {
    let validatedCount: SecretByteCount
    do {
      validatedCount = try SecretByteCount(byteCount)
    } catch {
      throw .secretMemory(error)
    }
    return try SecretBytes(byteCount: validatedCount) { output throws(KEMError) in
      try initializer(&output)
    }
  }

  static func random32ByteBlocks(
    count: Int,
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> SecretBytes {
    precondition(count > 0)
    let validatedCount: SecretByteCount
    do {
      validatedCount = try SecretByteCount(count * 32)
    } catch {
      throw .secretMemory(error)
    }
    do {
      return try SecretBytes(randomByteCount: validatedCount, using: entropy)
    } catch {
      throw .entropy(error)
    }
  }
}
