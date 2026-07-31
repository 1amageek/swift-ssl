import SwiftSSL

@main
enum FacadeValidationCommand {
  enum Failure: Error {
    case sha256
    case hmacSHA256
    case hkdfSHA256
    case errorContract
  }

  static func main() throws {
    try validateSHA256()
    try validateHMACSHA256()
    try validateHKDFSHA256()
    try validateFailureContracts()
    print("swift-ssl facade validation: ok")
  }

  private static func validateSHA256() throws {
    let input: ContiguousArray<UInt8> = [0x61, 0x62, 0x63]
    let expected: ContiguousArray<UInt8> = [
      0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    ]
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: SHA256.digestByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try hash(
        using: SHA256.self,
        input: input.span,
        output: &outputSpan
      )
    }
    guard output == expected else {
      throw Failure.sha256
    }

    var context = SHA256.makeContext()
    requireHashContext(context)
    try context.update(input.span)
    var contextualOutput = ContiguousArray<UInt8>(
      repeating: 0,
      count: SHA256.digestByteCount
    )
    do {
      var outputSpan = contextualOutput.mutableSpan
      try context.finalize(into: &outputSpan)
    }
    guard contextualOutput == expected else {
      throw Failure.sha256
    }
  }

  private static func validateHMACSHA256() throws {
    let key = ContiguousArray<UInt8>(repeating: 0x0B, count: 20)
    let message = ContiguousArray("Hi There".utf8)
    let expected: ContiguousArray<UInt8> = [
      0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
      0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
      0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
      0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7,
    ]
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA256.tagByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try authenticate(
        using: HMACSHA256.self,
        key: key.span,
        message: message.span,
        output: &outputSpan
      )
    }
    guard output == expected else {
      throw Failure.hmacSHA256
    }

    var context = try HMACSHA256.makeContext(
      authenticatingWith: key.span
    )
    requireMessageAuthenticationCodeContext(context)
    try context.update(message.span)
    var contextualOutput = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA256.tagByteCount
    )
    do {
      var outputSpan = contextualOutput.mutableSpan
      try context.finalize(into: &outputSpan)
    }
    guard contextualOutput == expected else {
      throw Failure.hmacSHA256
    }
  }

  private static func validateHKDFSHA256() throws {
    requireExtractAndExpandKeyDerivationFunction(HKDFSHA256.self)

    let inputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0x0B,
      count: 22
    )
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    let expected: ContiguousArray<UInt8> = [
      0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
      0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
      0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
      0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5,
    ]
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &outputSpan
      )
    }
    guard output == expected else {
      throw Failure.hkdfSHA256
    }
  }

  private static func validateFailureContracts() throws {
    let input: ContiguousArray<UInt8> = [0x61, 0x62, 0x63]
    let key = ContiguousArray<UInt8>(repeating: 0x0B, count: 32)

    for length in [
      SHA256.digestByteCount - 1,
      SHA256.digestByteCount + 1,
    ] {
      var output = ContiguousArray<UInt8>(
        repeating: 0xA5,
        count: length
      )
      let original = output
      var observedError: CryptoInputError?
      do {
        var outputSpan = output.mutableSpan
        try SHA256.hash(input.span, into: &outputSpan)
      } catch {
        observedError = error
      }
      guard
        observedError == .invalidOutputLength(
          expected: SHA256.digestByteCount,
          actual: length
        ),
        output == original
      else {
        throw Failure.errorContract
      }
    }

    for length in [
      HMACSHA256.tagByteCount - 1,
      HMACSHA256.tagByteCount + 1,
    ] {
      var output = ContiguousArray<UInt8>(
        repeating: 0x5A,
        count: length
      )
      let original = output
      var observedError: CryptoInputError?
      do {
        var outputSpan = output.mutableSpan
        try HMACSHA256.authenticate(
          input.span,
          using: key.span,
          into: &outputSpan
        )
      } catch {
        observedError = error
      }
      guard
        observedError == .invalidOutputLength(
          expected: HMACSHA256.tagByteCount,
          actual: length
        ),
        output == original
      else {
        throw Failure.errorContract
      }
    }

    var shortPseudorandomKeyOutput = ContiguousArray<UInt8>(
      repeating: 0xC3,
      count: HKDFSHA256.pseudorandomKeyByteCount - 1
    )
    let originalPseudorandomKeyOutput = shortPseudorandomKeyOutput
    var extractError: HKDFError?
    do {
      var outputSpan = shortPseudorandomKeyOutput.mutableSpan
      try HKDFSHA256.extract(
        inputKeyMaterial: input.span,
        salt: key.span,
        into: &outputSpan
      )
    } catch {
      extractError = error
    }
    guard
      extractError == .invalidPseudorandomKeyOutputLength(
        expected: HKDFSHA256.pseudorandomKeyByteCount,
        actual: shortPseudorandomKeyOutput.count
      ),
      shortPseudorandomKeyOutput == originalPseudorandomKeyOutput
    else {
      throw Failure.errorContract
    }

    var oversizedOutput = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.maximumOutputByteCount + 1
    )
    let originalOversizedOutput = oversizedOutput
    var expandError: HKDFError?
    do {
      var outputSpan = oversizedOutput.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: key.span,
        info: input.span,
        into: &outputSpan
      )
    } catch {
      expandError = error
    }
    guard
      expandError == .outputTooLong(
        limit: HKDFSHA256.maximumOutputByteCount,
        actual: oversizedOutput.count
      ),
      oversizedOutput == originalOversizedOutput
    else {
      throw Failure.errorContract
    }
  }

  private static func hash<Function: HashFunction>(
    using _: Function.Type,
    input: Span<UInt8>,
    output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try Function.hash(input, into: &output)
  }

  private static func authenticate<MAC: MessageAuthenticationCode>(
    using _: MAC.Type,
    key: Span<UInt8>,
    message: Span<UInt8>,
    output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try MAC.authenticate(message, using: key, into: &output)
  }

  private static func requireHashContext<Context: ~Copyable & HashContext>(
    _: borrowing Context
  ) {}

  private static func requireMessageAuthenticationCodeContext<
    Context: ~Copyable & MessageAuthenticationCodeContext
  >(
    _: borrowing Context
  ) {}

  private static func requireExtractAndExpandKeyDerivationFunction<
    Function: ExtractAndExpandKeyDerivationFunction
  >(
    _: Function.Type
  ) {}
}
