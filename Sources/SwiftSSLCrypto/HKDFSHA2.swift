import SwiftSSLCore

private enum HKDFSHA2Core<MAC: MessageAuthenticationCode> {
  static var digestByteCount: Int { MAC.tagByteCount }
  static var maximumOutputByteCount: Int { 255 * digestByteCount }

  static func extract(input: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>)
    throws(HKDFError)
  {
    guard output.count == digestByteCount else {
      throw .invalidPseudorandomKeyOutputLength(expected: digestByteCount, actual: output.count)
    }
    guard !overlap(input, output.span), !overlap(salt, output.span) else {
      throw .overlappingInputAndOutput
    }
    do { try MAC.authenticate(input, using: salt, into: &output) } catch { throw map(error) }
  }

  static func expand(prk: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>)
    throws(HKDFError)
  {
    guard prk.count >= digestByteCount else {
      throw .pseudorandomKeyTooShort(minimum: digestByteCount, actual: prk.count)
    }
    guard output.count <= maximumOutputByteCount else {
      throw .outputTooLong(limit: maximumOutputByteCount, actual: output.count)
    }
    guard !overlap(prk, output.span), !overlap(info, output.span) else {
      throw .overlappingInputAndOutput
    }
    guard !output.isEmpty else { return }

    do {
      var offset = 0
      var counter: UInt8 = 1
      while offset < output.count {
        var context = try MAC.makeContext(authenticatingWith: prk)
        if offset > 0 {
          try context.update(output.span.extracting((offset - digestByteCount)..<offset))
        }
        try context.update(info)
        try updateCounter(&context, value: counter)
        let count = min(digestByteCount, output.count - offset)
        if count == digestByteCount {
          var block = output._mutatingExtracting(offset..<(offset + count))
          try context.finalize(into: &block)
        } else {
          let temporary = UnsafeMutablePointer<UInt8>.allocate(capacity: digestByteCount)
          temporary.initialize(repeating: 0, count: digestByteCount)
          defer {
            SecureWipe.erase(temporary, byteCount: digestByteCount)
            temporary.deinitialize(count: digestByteCount)
            temporary.deallocate()
          }
          var block = MutableSpan(_unsafeStart: temporary, count: digestByteCount)
          try context.finalize(into: &block)
          var index = 0
          while index < count {
            output[offset + index] = temporary[index]
            index += 1
          }
        }
        offset += count
        counter &+= 1
      }
    } catch { throw map(error) }
  }

  private static func updateCounter(
    _ context: inout MAC.Context,
    value: UInt8
  ) throws(CryptoInputError) {
    var counter = value
    try withUnsafeBytes(of: &counter) { raw throws(CryptoInputError) -> Void in
      let pointer = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
      let buffer = UnsafeBufferPointer(start: pointer, count: 1)
      try context.update(Span(_unsafeElements: buffer))
    }
  }

  private static func overlap(_ first: Span<UInt8>, _ second: Span<UInt8>) -> Bool {
    guard !first.isEmpty, !second.isEmpty else { return false }
    return first.withUnsafeBufferPointer { firstBuffer in
      second.withUnsafeBufferPointer { secondBuffer in
        let firstStart = UInt(bitPattern: firstBuffer.baseAddress!)
        let secondStart = UInt(bitPattern: secondBuffer.baseAddress!)
        let (firstEnd, firstOverflow) = firstStart.addingReportingOverflow(UInt(firstBuffer.count))
        let (secondEnd, secondOverflow) = secondStart.addingReportingOverflow(
          UInt(secondBuffer.count))
        guard !firstOverflow, !secondOverflow else { return true }
        return firstStart < secondEnd && secondStart < firstEnd
      }
    }
  }

  private static func map(_ error: CryptoInputError) -> HKDFError {
    if case .inputTooLong(let limit) = error { return .inputTooLong(limit: limit) }
    return .primitiveFailure(error)
  }
}

public enum HKDFSHA384: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError
  public static let pseudorandomKeyByteCount = SHA384.digestByteCount
  public static let maximumOutputByteCount = 255 * SHA384.digestByteCount
  public static func extract(
    inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    try HKDFSHA2Core<HMACSHA384>.extract(input: inputKeyMaterial, salt: salt, into: &output)
  }
  public static func expand(
    pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    try HKDFSHA2Core<HMACSHA384>.expand(prk: pseudorandomKey, info: info, into: &output)
  }
}

public enum HKDFSHA512: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError
  public static let pseudorandomKeyByteCount = SHA512.digestByteCount
  public static let maximumOutputByteCount = 255 * SHA512.digestByteCount
  public static func extract(
    inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    try HKDFSHA2Core<HMACSHA512>.extract(input: inputKeyMaterial, salt: salt, into: &output)
  }
  public static func expand(
    pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    try HKDFSHA2Core<HMACSHA512>.expand(prk: pseudorandomKey, info: info, into: &output)
  }
}
