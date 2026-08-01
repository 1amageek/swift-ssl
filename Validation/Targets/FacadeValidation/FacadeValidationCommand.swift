import SwiftSSL

@main
enum FacadeValidationCommand {
  enum Failure: Error {
    case aesGCM
    case chacha20Poly1305
    case sha256
    case sha384512
    case hmacSHA256
    case hkdfSHA256
    case ed25519
    case p256
    case p256ECDSA
    case mlKEM
    case errorContract
  }

  static func main() throws {
    try validateAESGCM()
    try validateChaCha20Poly1305()
    try validateSHA256()
    try validateSHA384AndSHA512()
    try validateHMACSHA256()
    try validateHKDFSHA256()
    try validateEd25519()
    try validateP256()
    try validateMLKEM()
    try validateFailureContracts()
    print("swift-ssl facade validation: ok")
  }

  private static func validateMLKEM() throws {
    let keyEntropy = FixedEntropy(byte: 0x31)
    let pair = try MLKEM768.generateKeyPair(using: keyEntropy)
    let encapsulationEntropy = FixedEntropy(byte: 0x73)
    let encapsulated = try MLKEM768.encapsulate(
      to: pair.publicKey,
      using: encapsulationEntropy
    )
    let expected = encapsulated.sharedSecret.withBorrowedBytes { bytes in
      copy(bytes)
    }
    let recovered = try MLKEM768.decapsulate(
      encapsulated.encapsulation,
      using: pair.privateKey
    )
    guard recovered.withBorrowedBytes({ copy($0) }) == expected else {
      throw Failure.mlKEM
    }

    var inPlaceEncapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.encapsulationByteCount
    )
    var inPlaceSharedSecret = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.sharedSecretByteCount
    )
    var encapsulationOutput = inPlaceEncapsulation.mutableSpan
    var sharedSecretOutput = inPlaceSharedSecret.mutableSpan
    try MLKEM768.encapsulate(
      to: pair.publicKey,
      using: encapsulationEntropy,
      into: &encapsulationOutput,
      sharedSecret: &sharedSecretOutput
    )
    guard
      inPlaceEncapsulation == copy(encapsulated.encapsulation.span),
      inPlaceSharedSecret == expected
    else {
      throw Failure.mlKEM
    }

    var inPlaceRecovered = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM768.sharedSecretByteCount
    )
    var recoveredOutput = inPlaceRecovered.mutableSpan
    try MLKEM768.decapsulate(
      inPlaceEncapsulation.span,
      using: pair.privateKey,
      into: &recoveredOutput
    )
    guard inPlaceRecovered == expected else {
      throw Failure.mlKEM
    }

    var shortEncapsulation = ContiguousArray<UInt8>(
      repeating: 0xC3,
      count: MLKEM768.encapsulationByteCount - 1
    )
    var untouchedSharedSecret = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: MLKEM768.sharedSecretByteCount
    )
    let originalShortEncapsulation = shortEncapsulation
    let originalSharedSecret = untouchedSharedSecret
    var observedError: KEMError?
    do {
      var shortOutput = shortEncapsulation.mutableSpan
      var secretOutput = untouchedSharedSecret.mutableSpan
      try MLKEM768.encapsulate(
        to: pair.publicKey,
        using: encapsulationEntropy,
        into: &shortOutput,
        sharedSecret: &secretOutput
      )
    } catch {
      observedError = error
    }
    guard
      observedError == .invalidEncapsulationLength(
        expected: MLKEM768.encapsulationByteCount,
        actual: MLKEM768.encapsulationByteCount - 1
      ),
      shortEncapsulation == originalShortEncapsulation,
      untouchedSharedSecret == originalSharedSecret
    else {
      throw Failure.errorContract
    }
  }

  private static func validateAESGCM() throws {
    let key: ContiguousArray<UInt8> = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    let nonce: ContiguousArray<UInt8> = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    let plaintext: ContiguousArray<UInt8> = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    let expected: ContiguousArray<UInt8> = [
      0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
      0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
      0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
      0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    var cipher = try AESGCM(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else {
      throw Failure.aesGCM
    }

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: Span(_unsafeElements: UnsafeBufferPointer<UInt8>(start: nil, count: 0)),
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else {
      throw Failure.aesGCM
    }
  }

  private static func validateChaCha20Poly1305() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>()
    let expected: ContiguousArray<UInt8> = [
      0x4E, 0xB9, 0x72, 0xC9, 0xA8, 0xFB, 0x3A, 0x1B,
      0x38, 0x2B, 0xB4, 0xD3, 0x6F, 0x5F, 0xFA, 0xD1,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    var cipher = try ChaCha20Poly1305(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else { throw Failure.chacha20Poly1305 }

    var recovered = ContiguousArray<UInt8>()
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else { throw Failure.chacha20Poly1305 }
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

  private static func validateSHA384AndSHA512() throws {
    let input = ContiguousArray("abc".utf8)
    let expected384 = ContiguousArray<UInt8>([
      0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
    ])
    let expected512 = ContiguousArray<UInt8>([
      0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
    ])
    var output384 = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
    var output384Span = output384.mutableSpan
    try SHA384.hash(input.span, into: &output384Span)
    var output512 = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
    var output512Span = output512.mutableSpan
    try SHA512.hash(input.span, into: &output512Span)
    guard output384 == expected384, output512 == expected512 else { throw Failure.sha384512 }
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

  private static func validateEd25519() throws {
    let publicKeyBytes = ContiguousArray<UInt8>([
      0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7,
      0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
      0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25,
      0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
    ])
    let signature = ContiguousArray<UInt8>([
      0xE5, 0x56, 0x43, 0x00, 0xC3, 0x60, 0xAC, 0x72,
      0x90, 0x86, 0xE2, 0xCC, 0x80, 0x6E, 0x82, 0x8A,
      0x84, 0x87, 0x7F, 0x1E, 0xB8, 0xE5, 0xD9, 0x74,
      0xD8, 0x73, 0xE0, 0x65, 0x22, 0x49, 0x01, 0x55,
      0x5F, 0xB8, 0x82, 0x15, 0x90, 0xA3, 0x3B, 0xAC,
      0xC6, 0x1E, 0x39, 0x70, 0x1C, 0xF9, 0xB4, 0x6B,
      0xD2, 0x5B, 0xF5, 0xF0, 0x59, 0x5B, 0xBE, 0x24,
      0x65, 0x51, 0x41, 0x43, 0x8E, 0x7A, 0x10, 0x0B,
    ])
    let emptyMessage = ContiguousArray<UInt8>()
    let modifiedMessage = ContiguousArray<UInt8>([0])
    let publicKey = try Ed25519PublicKey(bytes: publicKeyBytes.span)

    guard try Ed25519.verify(
      signature: signature.span,
      message: emptyMessage.span,
      using: publicKey
    ) else {
      throw Failure.ed25519
    }
    guard try !Ed25519.verify(
      signature: signature.span,
      message: modifiedMessage.span,
      using: publicKey
    ) else {
      throw Failure.ed25519
    }
  }

  private static func validateP256() throws {
    let signingPublicKey = ContiguousArray<UInt8>([
      0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42,
      0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
      0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33,
      0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
      0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
      0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
      0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
      0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
      0xF5,
    ])
    let digest = ContiguousArray<UInt8>([
      0x17, 0x2B, 0x12, 0x96, 0xFE, 0xDD, 0xD5, 0xE2,
      0xC0, 0xB6, 0x30, 0x06, 0x15, 0x14, 0x2D, 0x3C,
      0x4F, 0x6D, 0x37, 0x5E, 0x5C, 0xB7, 0x0E, 0xD8,
      0xCF, 0xA9, 0x22, 0x0C, 0xCE, 0xB9, 0x4B, 0xE2,
    ])
    let rawSignature = ContiguousArray<UInt8>([
      0xB1, 0x86, 0x79, 0x69, 0x06, 0xE2, 0x66, 0x21,
      0xD8, 0x94, 0x0D, 0xDD, 0xF7, 0x93, 0x30, 0xF3,
      0x8F, 0xB9, 0xEB, 0x6D, 0x8D, 0x8D, 0x88, 0x23,
      0x6E, 0x72, 0x23, 0xC7, 0x11, 0x19, 0xC8, 0xCE,
      0xFA, 0x03, 0x75, 0x45, 0xB6, 0x06, 0xE0, 0x53,
      0xDB, 0xFB, 0x53, 0xAF, 0xF1, 0xD1, 0x82, 0x25,
      0x0E, 0x1C, 0xD6, 0xBE, 0xF8, 0xEF, 0x5B, 0x6F,
      0x56, 0xC3, 0x5C, 0x0B, 0x3E, 0xE8, 0xAF, 0x64,
    ])
    let signingKey = try P256PublicKey(bytes: signingPublicKey.span)
    guard try P256ECDSA.verify(
      signature: rawSignature.span,
      messageHash: digest.span,
      publicKey: signingKey
    ) else {
      throw Failure.p256ECDSA
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

  private static func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private struct FixedEntropy: EntropySource {
    let byte: UInt8

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
    }
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
