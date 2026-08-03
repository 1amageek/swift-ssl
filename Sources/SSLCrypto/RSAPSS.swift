import SSLCore

/// A validated RSA public key for verification-only operations.
public struct RSAPublicKey: Sendable, Hashable {
  public static let minimumModulusByteCount = 256
  public static let maximumModulusByteCount = 512

  private let modulus: OwnedBytes
  public let exponent: UInt64

  public init(
    modulus: Span<UInt8>,
    exponent: UInt64
  ) throws(CryptoInputError) {
    guard modulus.count >= Self.minimumModulusByteCount,
      modulus.count <= Self.maximumModulusByteCount
    else {
      throw .invalidLength(expected: Self.minimumModulusByteCount, actual: modulus.count)
    }
    guard modulus[0] != 0,
      modulus[modulus.count - 1] & 1 == 1,
      exponent >= 3,
      exponent & 1 == 1,
      exponent <= UInt64(Int.max)
    else {
      throw .nonCanonicalEncoding
    }
    self.modulus = OwnedBytes(copying: modulus)
    self.exponent = exponent
  }

  /// Parses a canonical PKCS #1 `RSAPublicKey` document.
  public init(pkcs1DER: Span<UInt8>) throws(CryptoInputError) {
    var offset = 0
    guard Self.readByte(pkcs1DER, at: &offset) == 0x30 else {
      throw .nonCanonicalEncoding
    }
    let sequenceByteCount = try Self.readDERLength(pkcs1DER, at: &offset)
    guard sequenceByteCount == pkcs1DER.count - offset else {
      throw .nonCanonicalEncoding
    }
    let modulus = try Self.readPositiveInteger(pkcs1DER, at: &offset)
    let encodedExponent = try Self.readPositiveInteger(pkcs1DER, at: &offset)
    guard offset == pkcs1DER.count,
      encodedExponent.count <= MemoryLayout<UInt64>.size
    else {
      throw .nonCanonicalEncoding
    }
    var exponent: UInt64 = 0
    var index = 0
    while index < encodedExponent.count {
      exponent = (exponent << 8) | UInt64(encodedExponent[index])
      index += 1
    }
    try self.init(modulus: modulus, exponent: exponent)
  }

  public var modulusByteCount: Int { modulus.count }

  public borrowing func withModulusBytes<Result, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(modulus.span)
  }

  /// Encodes this key as a canonical PKCS #1 `RSAPublicKey` document.
  public func pkcs1DER() -> ContiguousArray<UInt8> {
    var body = ContiguousArray<UInt8>()
    Self.appendPositiveInteger(modulus.span, to: &body)
    var exponentBytes = ContiguousArray<UInt8>()
    var value = exponent
    repeat {
      exponentBytes.insert(UInt8(truncatingIfNeeded: value), at: 0)
      value >>= 8
    } while value != 0
    Self.appendPositiveInteger(exponentBytes.span, to: &body)

    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(body.count + 4)
    result.append(0x30)
    Self.appendDERLength(body.count, to: &result)
    result.append(contentsOf: body)
    return result
  }

  private static func readByte(
    _ bytes: Span<UInt8>,
    at offset: inout Int
  ) -> UInt8? {
    guard offset < bytes.count else { return nil }
    let value = bytes[offset]
    offset += 1
    return value
  }

  private static func readDERLength(
    _ bytes: Span<UInt8>,
    at offset: inout Int
  ) throws(CryptoInputError) -> Int {
    guard let first = readByte(bytes, at: &offset) else {
      throw .nonCanonicalEncoding
    }
    if first < 0x80 { return Int(first) }
    let byteCount = Int(first & 0x7F)
    guard byteCount > 0,
      byteCount <= MemoryLayout<Int>.size,
      offset <= bytes.count - byteCount,
      bytes[offset] != 0
    else {
      throw .nonCanonicalEncoding
    }
    var length = 0
    var index = 0
    while index < byteCount {
      let multiplied = length.multipliedReportingOverflow(by: 256)
      guard !multiplied.overflow else { throw .nonCanonicalEncoding }
      let added = multiplied.partialValue.addingReportingOverflow(
        Int(bytes[offset + index])
      )
      guard !added.overflow else { throw .nonCanonicalEncoding }
      length = added.partialValue
      index += 1
    }
    guard length >= 128 else { throw .nonCanonicalEncoding }
    offset += byteCount
    return length
  }

  private static func readPositiveInteger(
    _ bytes: Span<UInt8>,
    at offset: inout Int
  ) throws(CryptoInputError) -> Span<UInt8> {
    guard readByte(bytes, at: &offset) == 0x02 else {
      throw .nonCanonicalEncoding
    }
    let byteCount = try readDERLength(bytes, at: &offset)
    guard byteCount > 0, offset <= bytes.count - byteCount else {
      throw .nonCanonicalEncoding
    }
    let integer = bytes.extracting(offset..<(offset + byteCount))
    offset += byteCount
    guard integer[0] & 0x80 == 0 else { throw .nonCanonicalEncoding }
    if integer[0] == 0 {
      guard byteCount > 1, integer[1] & 0x80 != 0 else {
        throw .nonCanonicalEncoding
      }
      return integer.extracting(1..<integer.count)
    }
    return integer
  }

  private static func appendPositiveInteger(
    _ bytes: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) {
    var first = 0
    while first + 1 < bytes.count, bytes[first] == 0 {
      first += 1
    }
    let needsPadding = bytes[first] & 0x80 != 0
    output.append(0x02)
    appendDERLength(bytes.count - first + (needsPadding ? 1 : 0), to: &output)
    if needsPadding { output.append(0) }
    var index = first
    while index < bytes.count {
      output.append(bytes[index])
      index += 1
    }
  }

  private static func appendDERLength(
    _ length: Int,
    to output: inout ContiguousArray<UInt8>
  ) {
    if length < 128 {
      output.append(UInt8(length))
      return
    }
    var encoded = ContiguousArray<UInt8>()
    var value = length
    while value != 0 {
      encoded.insert(UInt8(truncatingIfNeeded: value), at: 0)
      value >>= 8
    }
    output.append(0x80 | UInt8(encoded.count))
    output.append(contentsOf: encoded)
  }
}

public enum RSAPSSHash: Sendable, Hashable {
  case sha256
  case sha384
  case sha512

  public var digestByteCount: Int {
    switch self {
    case .sha256: return SHA256.digestByteCount
    case .sha384: return SHA384.digestByteCount
    case .sha512: return SHA512.digestByteCount
    }
  }
}

/// RSA-PSS signing and verification with SHA-2 and MGF1.
///
/// Verification uses public-input arithmetic. Signing keeps the private
/// exponent in wipe-on-destroy storage, uses fixed-loop mask-selected secret
/// exponentiation, and performs a public-key self-check before releasing a
/// signature. The randomized PSS encoding also prevents repeated messages from
/// presenting a repeated private-operation input.
public enum RSAPSS {
  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing RSAPrivateKey,
    hash: RSAPSSHash = .sha256
  ) throws(RSASigningError) -> ContiguousArray<UInt8> {
    try sign(
      messageHash: messageHash,
      using: privateKey,
      hash: hash,
      entropy: SystemEntropySource()
    )
  }

  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing RSAPrivateKey,
    hash: RSAPSSHash = .sha256,
    entropy: borrowing any EntropySource
  ) throws(RSASigningError) -> ContiguousArray<UInt8> {
    guard messageHash.count == hash.digestByteCount else {
      throw .crypto(
        .invalidLength(
          expected: hash.digestByteCount,
          actual: messageHash.count
        )
      )
    }
    let publicKey = privateKey.publicKey
    let modulus = publicKey.withModulusBytes { RSAUInt(bytes: $0) }
    let encodedMessageBitCount = modulus.bitWidth - 1
    let encodedMessageByteCount = (encodedMessageBitCount + 7) / 8
    let saltByteCount = hash.digestByteCount
    let dataBlockByteCount = encodedMessageByteCount - hash.digestByteCount - 1
    let paddingByteCount = dataBlockByteCount - saltByteCount - 1
    guard paddingByteCount >= 0 else {
      throw .crypto(
        .invalidLength(
          expected: hash.digestByteCount * 2 + 2,
          actual: encodedMessageByteCount
        )
      )
    }

    var salt = ContiguousArray<UInt8>(repeating: 0, count: saltByteCount)
    do {
      var destination = salt.mutableSpan
      try entropy.fill(&destination)
    } catch let error {
      throw .entropy(error)
    }
    var hashInput = ContiguousArray<UInt8>(
      repeating: 0,
      count: 8 + messageHash.count + salt.count
    )
    var index = 0
    while index < messageHash.count {
      hashInput[8 + index] = messageHash[index]
      index += 1
    }
    index = 0
    while index < salt.count {
      hashInput[8 + messageHash.count + index] = salt[index]
      index += 1
    }
    let encodedHash: ContiguousArray<UInt8>
    do {
      encodedHash = try hashDigest(hashInput.span, hash: hash)
    } catch let error {
      throw .crypto(error)
    }
    let dataBlockMask: ContiguousArray<UInt8>
    do {
      dataBlockMask = try mgf1(
        seed: encodedHash.span,
        count: dataBlockByteCount,
        hash: hash
      )
    } catch let error {
      throw .crypto(error)
    }

    var encodedMessage = ContiguousArray<UInt8>(
      repeating: 0,
      count: encodedMessageByteCount
    )
    index = 0
    while index < dataBlockByteCount {
      let dataBlockByte: UInt8
      if index < paddingByteCount {
        dataBlockByte = 0
      } else if index == paddingByteCount {
        dataBlockByte = 1
      } else {
        dataBlockByte = salt[index - paddingByteCount - 1]
      }
      encodedMessage[index] = dataBlockByte ^ dataBlockMask[index]
      index += 1
    }
    let unusedBitCount = 8 * encodedMessageByteCount - encodedMessageBitCount
    if unusedBitCount > 0 {
      encodedMessage[0] &= UInt8(0xFF >> UInt8(unusedBitCount))
    }
    index = 0
    while index < encodedHash.count {
      encodedMessage[dataBlockByteCount + index] = encodedHash[index]
      index += 1
    }
    encodedMessage[encodedMessage.count - 1] = 0xBC

    let signature = privateKey.withPrivateExponent { exponent in
      let encoded = RSAUInt(bytes: encodedMessage.span)
      let signed = RSAUInt.modularPowerSecret(
        encoded,
        exponent: exponent,
        modulus: modulus
      )
      return signed.encoded(byteCount: publicKey.modulusByteCount)
    }
    let verified: Bool
    do {
      verified = try verify(
        signature: signature.span,
        messageHash: messageHash,
        publicKey: publicKey,
        hash: hash,
        saltLength: saltByteCount
      )
    } catch let error {
      throw .crypto(error)
    }
    guard verified else { throw .selfCheckFailed }
    return signature
  }

  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    publicKey: borrowing RSAPublicKey,
    hash: RSAPSSHash,
    saltLength: Int? = nil
  ) throws(CryptoInputError) -> Bool {
    let modulusBytes = publicKey.modulusByteCount
    guard signature.count == modulusBytes else {
      throw .invalidLength(expected: modulusBytes, actual: signature.count)
    }
    guard messageHash.count == hash.digestByteCount else {
      throw .invalidLength(expected: hash.digestByteCount, actual: messageHash.count)
    }
    let selectedSaltLength = saltLength ?? hash.digestByteCount
    guard selectedSaltLength >= 0 else {
      throw .invalidLength(expected: 0, actual: selectedSaltLength)
    }

    let modulus = publicKey.withModulusBytes { bytes in
      RSAUInt(bytes: bytes)
    }
    let encodedMessageByteCount = (modulus.bitWidth - 1 + 7) / 8
    let maximumSaltLength = encodedMessageByteCount - hash.digestByteCount - 2
    guard selectedSaltLength <= maximumSaltLength else {
      throw .invalidLength(expected: maximumSaltLength, actual: selectedSaltLength)
    }
    let encoded = RSAUInt(bytes: signature)
    guard encoded < modulus else { throw .nonCanonicalEncoding }
    let recovered = RSAUInt.modularPower(
      encoded,
      exponent: publicKey.exponent,
      modulus: modulus
    )
    let encodedBytes = recovered.encoded(byteCount: modulusBytes)
    return try verifyEncodedMessage(
      encodedBytes: encodedBytes.span,
      messageHash: messageHash,
      hash: hash,
      saltLength: selectedSaltLength,
      modulus: modulus
    )
  }

  private static func verifyEncodedMessage(
    encodedBytes: Span<UInt8>,
    messageHash: Span<UInt8>,
    hash: RSAPSSHash,
    saltLength: Int,
    modulus: RSAUInt
  ) throws(CryptoInputError) -> Bool {
    let modulusBitCount = modulus.bitWidth
    let emBitCount = modulusBitCount - 1
    let emByteCount = (emBitCount + 7) / 8
    guard encodedBytes.count >= emByteCount else { return false }
    let leadingCount = encodedBytes.count - emByteCount
    let encodedMessage = encodedBytes.extracting(leadingCount..<encodedBytes.count)
    guard !encodedMessage.isEmpty else { return false }

    let digestByteCount = hash.digestByteCount
    guard emByteCount >= digestByteCount + saltLength + 2 else { return false }
    guard encodedMessage[encodedMessage.count - 1] == 0xBC else { return false }
    let unusedBits = 8 * emByteCount - emBitCount
    if unusedBits > 0 {
      let mask = UInt8(0xFF >> UInt8(unusedBits))
      guard encodedMessage[0] & ~mask == 0 else { return false }
    }

    let dbByteCount = emByteCount - digestByteCount - 1
    let maskedDB = encodedMessage.extracting(0..<dbByteCount)
    let recoveredHash = encodedMessage.extracting(dbByteCount..<(dbByteCount + digestByteCount))
    let mask = try mgf1(
      seed: recoveredHash,
      count: dbByteCount,
      hash: hash
    )
    var db = ContiguousArray<UInt8>(repeating: 0, count: dbByteCount)
    var index = 0
    while index < dbByteCount {
      db[index] = maskedDB[index] ^ mask[index]
      index += 1
    }
    if unusedBits > 0 {
      db[0] &= UInt8(0xFF >> UInt8(unusedBits))
    }

    let paddingCount = dbByteCount - saltLength - 1
    guard paddingCount >= 0 else { return false }
    index = 0
    while index < paddingCount {
      guard db[index] == 0 else { return false }
      index += 1
    }
    guard db[paddingCount] == 1 else { return false }
    let salt = db.span.extracting((paddingCount + 1)..<dbByteCount)

    var validationInput = ContiguousArray<UInt8>(
      repeating: 0, count: 8 + digestByteCount + saltLength)
    var messageIndex = 0
    while messageIndex < digestByteCount {
      validationInput[8 + messageIndex] = messageHash[messageIndex]
      messageIndex += 1
    }
    var saltIndex = 0
    while saltIndex < saltLength {
      validationInput[8 + digestByteCount + saltIndex] = salt[saltIndex]
      saltIndex += 1
    }
    let expectedHash = try hashDigest(validationInput.span, hash: hash)
    return ConstantTime.equal(recoveredHash, expectedHash.span)
  }

  private static func mgf1(
    seed: Span<UInt8>,
    count: Int,
    hash: RSAPSSHash
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    guard count >= 0, count <= 16 * 1024 * 1024 else {
      throw .invalidLength(expected: 0, actual: count)
    }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(count)
    var counter: UInt32 = 0
    while result.count < count {
      var input = ContiguousArray<UInt8>(repeating: 0, count: seed.count + 4)
      var index = 0
      while index < seed.count {
        input[index] = seed[index]
        index += 1
      }
      input[seed.count] = UInt8(truncatingIfNeeded: counter >> 24)
      input[seed.count + 1] = UInt8(truncatingIfNeeded: counter >> 16)
      input[seed.count + 2] = UInt8(truncatingIfNeeded: counter >> 8)
      input[seed.count + 3] = UInt8(truncatingIfNeeded: counter)
      let digest = try hashDigest(input.span, hash: hash)
      let remaining = count - result.count
      let appendCount = min(remaining, digest.count)
      var appendIndex = 0
      while appendIndex < appendCount {
        result.append(digest[appendIndex])
        appendIndex += 1
      }
      guard counter != UInt32.max else {
        throw .invalidLength(expected: count, actual: result.count)
      }
      counter += 1
    }
    return result
  }

  private static func hashDigest(
    _ input: Span<UInt8>,
    hash: RSAPSSHash
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: hash.digestByteCount)
    var span = output.mutableSpan
    switch hash {
    case .sha256:
      try SHA256.hash(input, into: &span)
    case .sha384:
      try SHA384.hash(input, into: &span)
    case .sha512:
      try SHA512.hash(input, into: &span)
    }
    return output
  }
}

struct RSAUInt: Equatable, Comparable {
  let words: ContiguousArray<UInt32>

  init(bytes: Span<UInt8>) {
    var result = ContiguousArray<UInt32>(repeating: 0, count: max(1, (bytes.count + 3) / 4))
    var index = 0
    while index < bytes.count {
      let source = bytes.count - 1 - index
      result[index / 4] |= UInt32(bytes[source]) << UInt32((index & 3) * 8)
      index += 1
    }
    self.words = result
  }

  init(words: ContiguousArray<UInt32>) { self.words = words }

  static func one(count: Int) -> RSAUInt {
    var words = ContiguousArray<UInt32>(repeating: 0, count: count)
    words[0] = 1
    return RSAUInt(words: words)
  }

  var bitWidth: Int {
    var index = words.count - 1
    while index > 0, words[index] == 0 { index -= 1 }
    let word = words[index]
    if word == 0 { return 0 }
    return index * 32 + (32 - word.leadingZeroBitCount)
  }

  var isZero: Bool { words.allSatisfy { $0 == 0 } }

  func encoded(byteCount: Int) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
    var index = 0
    while index < byteCount {
      let word = index / 4
      if word < words.count {
        result[byteCount - 1 - index] = UInt8(
          truncatingIfNeeded: words[word] >> UInt32((index & 3) * 8))
      }
      index += 1
    }
    return result
  }

  static func modularPower(
    _ base: RSAUInt,
    exponent: UInt64,
    modulus: RSAUInt
  ) -> RSAUInt {
    precondition(!modulus.isZero && modulus.words[0] & 1 == 1)
    let wordCount = modulus.words.count
    let radixBitCount = wordCount * UInt32.bitWidth
    let one = RSAUInt.one(count: wordCount)
    var result = one.shiftedIntoMontgomeryDomain(
      radixBitCount: radixBitCount,
      modulus: modulus
    )
    var value = base.modulo(modulus).shiftedIntoMontgomeryDomain(
      radixBitCount: radixBitCount,
      modulus: modulus
    )
    var exponent = exponent
    while exponent != 0 {
      if exponent & 1 != 0 {
        result = result.montgomeryMultiply(value, modulus: modulus)
      }
      exponent >>= 1
      if exponent != 0 {
        value = value.montgomeryMultiply(value, modulus: modulus)
      }
    }
    return result.montgomeryMultiply(one, modulus: modulus)
  }

  fileprivate static func modularPowerSecret(
    _ base: RSAUInt,
    exponent: Span<UInt8>,
    modulus: RSAUInt
  ) -> RSASecretWords {
    precondition(!modulus.isZero && modulus.words[0] & 1 == 1)
    let wordCount = modulus.words.count
    let radixBitCount = wordCount * UInt32.bitWidth
    let one = RSAUInt.one(count: wordCount)
    let oneMontgomery = one.shiftedIntoMontgomeryDomain(
      radixBitCount: radixBitCount,
      modulus: modulus
    )
    var result = RSASecretWords(copying: oneMontgomery.words, count: wordCount)
    var value = base.modulo(modulus).shiftedIntoMontgomeryDomain(
      radixBitCount: radixBitCount,
      modulus: modulus
    )

    var byteIndex = exponent.count
    while byteIndex > 0 {
      byteIndex -= 1
      var bitIndex = 0
      while bitIndex < 8 {
        let bit = UInt32((exponent[byteIndex] >> UInt8(bitIndex)) & 1)
        let mask = UInt32(0) &- bit
        let candidate = montgomeryMultiplySecret(
          result,
          value,
          modulus: modulus
        )
        result.select(candidate, mask: mask)
        value = value.montgomeryMultiply(value, modulus: modulus)
        bitIndex += 1
      }
    }
    return montgomeryMultiplySecret(result, one, modulus: modulus)
  }

  static func privateExponentMatches(
    _ exponent: Span<UInt8>,
    publicExponent: UInt64,
    modulus: RSAUInt
  ) -> Bool {
    let wordCount = modulus.words.count
    var baseWords = ContiguousArray<UInt32>(repeating: 0, count: wordCount)
    baseWords[0] = 2
    let base = RSAUInt(words: baseWords)
    let privateResult = modularPowerSecret(
      base,
      exponent: exponent,
      modulus: modulus
    )
    let privateResultBytes = privateResult.encoded(
      byteCount: wordCount * MemoryLayout<UInt32>.size
    )
    let recovered = modularPower(
      RSAUInt(bytes: privateResultBytes.span),
      exponent: publicExponent,
      modulus: modulus
    )
    return !(recovered < base) && !(base < recovered)
  }

  static func multiply(_ lhs: RSAUInt, _ rhs: RSAUInt) -> RSAUInt {
    var result = ContiguousArray<UInt32>(
      repeating: 0,
      count: lhs.words.count + rhs.words.count
    )
    var outer = 0
    while outer < lhs.words.count {
      var carry: UInt64 = 0
      var inner = 0
      while inner < rhs.words.count {
        let position = outer + inner
        let value = UInt64(lhs.words[outer]) * UInt64(rhs.words[inner])
          + UInt64(result[position]) + carry
        result[position] = UInt32(truncatingIfNeeded: value)
        carry = value >> 32
        inner += 1
      }
      var position = outer + rhs.words.count
      while carry != 0 {
        precondition(position < result.count)
        let value = UInt64(result[position]) + carry
        result[position] = UInt32(truncatingIfNeeded: value)
        carry = value >> 32
        position += 1
      }
      outer += 1
    }
    return RSAUInt(words: result)
  }

  private static func montgomeryMultiplySecret(
    _ secret: borrowing RSASecretWords,
    _ publicValue: RSAUInt,
    modulus: RSAUInt
  ) -> RSASecretWords {
    let count = modulus.words.count
    precondition(secret.count == count && publicValue.words.count == count)
    let reductionFactor = 0 &- inverseModuloWord(modulus.words[0])
    var accumulator = RSASecretWords(count: count * 2 + 2)
    var outer = 0
    while outer < count {
      let multiplier = publicValue.words[outer]
      var carry: UInt64 = 0
      var inner = 0
      while inner < count {
        let position = outer + inner
        let value =
          UInt64(secret.word(at: inner)) * UInt64(multiplier)
          + UInt64(accumulator.word(at: position)) + carry
        accumulator.setWord(UInt32(truncatingIfNeeded: value), at: position)
        carry = value >> 32
        inner += 1
      }
      accumulator.addCarry(carry, at: outer + count)

      let reductionWord = accumulator.word(at: outer) &* reductionFactor
      carry = 0
      inner = 0
      while inner < count {
        let position = outer + inner
        let value =
          UInt64(reductionWord) * UInt64(modulus.words[inner])
          + UInt64(accumulator.word(at: position)) + carry
        accumulator.setWord(UInt32(truncatingIfNeeded: value), at: position)
        carry = value >> 32
        inner += 1
      }
      accumulator.addCarry(carry, at: outer + count)
      outer += 1
    }

    var result = RSASecretWords(count: count)
    var borrow: UInt64 = 0
    var index = 0
    while index < count {
      let source = UInt64(accumulator.word(at: count + index))
      let widened = (UInt64(1) << 32) + source
        - UInt64(modulus.words[index]) - borrow
      result.setWord(UInt32(truncatingIfNeeded: widened), at: index)
      borrow = 1 &- (widened >> 32)
      index += 1
    }
    let high = accumulator.word(at: count * 2)
      | accumulator.word(at: count * 2 + 1)
    let highNonzero = (high | (0 &- high)) >> 31
    let useSubtraction = highNonzero | UInt32(1 &- borrow)
    let mask = UInt32(0) &- useSubtraction
    index = 0
    while index < count {
      let unreduced = accumulator.word(at: count + index)
      let reduced = result.word(at: index)
      result.setWord(
        (unreduced & ~mask) | (reduced & mask),
        at: index
      )
      index += 1
    }
    return result
  }

  func modulo(_ modulus: RSAUInt) -> RSAUInt {
    var value = self
    while value >= modulus { value = value - modulus }
    return value
  }

  private func shiftedIntoMontgomeryDomain(
    radixBitCount: Int,
    modulus: RSAUInt
  ) -> RSAUInt {
    var result = self
    var bit = 0
    while bit < radixBitCount {
      result = result.modularDouble(modulus: modulus)
      bit += 1
    }
    return result
  }

  private func modularDouble(modulus: RSAUInt) -> RSAUInt {
    let count = modulus.words.count
    var doubled = ContiguousArray<UInt32>(repeating: 0, count: count)
    var carry: UInt64 = 0
    var index = 0
    while index < count {
      let word = index < words.count ? words[index] : 0
      let value = UInt64(word) << 1 | carry
      doubled[index] = UInt32(truncatingIfNeeded: value)
      carry = value >> 32
      index += 1
    }
    let candidate = RSAUInt(words: doubled)
    if carry != 0 || candidate >= modulus {
      return candidate.subtractingModulusWithOverflow(modulus)
    }
    return candidate
  }

  private func montgomeryMultiply(
    _ other: RSAUInt,
    modulus: RSAUInt
  ) -> RSAUInt {
    let count = modulus.words.count
    let reductionFactor = 0 &- Self.inverseModuloWord(modulus.words[0])
    var accumulator = ContiguousArray<UInt32>(repeating: 0, count: count * 2 + 2)
    var outer = 0
    while outer < count {
      let multiplier = outer < other.words.count ? other.words[outer] : 0
      var carry: UInt64 = 0
      var inner = 0
      while inner < count {
        let multiplicand = inner < words.count ? words[inner] : 0
        let position = outer + inner
        let value =
          UInt64(multiplicand) * UInt64(multiplier)
          + UInt64(accumulator[position]) + carry
        accumulator[position] = UInt32(truncatingIfNeeded: value)
        carry = value >> 32
        inner += 1
      }
      Self.addCarry(carry, at: outer + count, to: &accumulator)

      let reductionWord = accumulator[outer] &* reductionFactor
      carry = 0
      inner = 0
      while inner < count {
        let position = outer + inner
        let value =
          UInt64(reductionWord) * UInt64(modulus.words[inner])
          + UInt64(accumulator[position]) + carry
        accumulator[position] = UInt32(truncatingIfNeeded: value)
        carry = value >> 32
        inner += 1
      }
      Self.addCarry(carry, at: outer + count, to: &accumulator)
      outer += 1
    }

    var reducedWords = ContiguousArray<UInt32>(repeating: 0, count: count)
    var index = 0
    while index < count {
      reducedWords[index] = accumulator[index + count]
      index += 1
    }
    let reduced = RSAUInt(words: reducedWords)
    if accumulator[count * 2] != 0 || reduced >= modulus {
      return reduced.subtractingModulusWithOverflow(modulus)
    }
    return reduced
  }

  private static func inverseModuloWord(_ oddWord: UInt32) -> UInt32 {
    precondition(oddWord & 1 == 1)
    var inverse: UInt32 = 1
    var iteration = 0
    while iteration < 5 {
      inverse &*= 2 &- oddWord &* inverse
      iteration += 1
    }
    return inverse
  }

  private static func addCarry(
    _ initialCarry: UInt64,
    at initialIndex: Int,
    to accumulator: inout ContiguousArray<UInt32>
  ) {
    var carry = initialCarry
    var index = initialIndex
    while carry != 0 {
      precondition(index < accumulator.count)
      let value = UInt64(accumulator[index]) + carry
      accumulator[index] = UInt32(truncatingIfNeeded: value)
      carry = value >> 32
      index += 1
    }
  }

  private func subtractingModulusWithOverflow(_ modulus: RSAUInt) -> RSAUInt {
    var result = words
    var borrow: UInt64 = 0
    var index = 0
    while index < result.count {
      let minuend = UInt64(result[index])
      let subtrahend = UInt64(modulus.words[index]) + borrow
      if minuend < subtrahend {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
        borrow = 0
      }
      index += 1
    }
    return RSAUInt(words: result)
  }

  static func - (lhs: RSAUInt, rhs: RSAUInt) -> RSAUInt {
    var result = ContiguousArray<UInt32>(repeating: 0, count: lhs.words.count)
    var borrow: UInt64 = 0
    var index = 0
    while index < result.count {
      let minuend = UInt64(lhs.words[index])
      let subtrahend = UInt64(rhs.words[index]) + borrow
      if minuend < subtrahend {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
        borrow = 0
      }
      index += 1
    }
    return RSAUInt(words: result)
  }

  static func < (lhs: RSAUInt, rhs: RSAUInt) -> Bool {
    var index = max(lhs.words.count, rhs.words.count) - 1
    while index >= 0 {
      let left = index < lhs.words.count ? lhs.words[index] : 0
      let right = index < rhs.words.count ? rhs.words[index] : 0
      if left != right { return left < right }
      index -= 1
    }
    return false
  }
}

fileprivate struct RSASecretWords: ~Copyable {
  private let pointer: UnsafeMutablePointer<UInt32>
  let count: Int

  // Unsafe boundary invariants:
  // - This value uniquely owns count initialized UInt32 words.
  // - count is bounded by the validated 4096-bit RSA modulus plus scratch space.
  // - Word access is range checked and no pointer escapes this type.
  // - The allocation is bound to UInt32 once, erased exactly once, then released.
  // - The owner remains within one synchronous signing operation and crosses no
  //   Sendable or exclusivity boundary.
  init(count: Int) {
    precondition(count > 0 && count <= 258)
    pointer = UnsafeMutablePointer<UInt32>.allocate(capacity: count)
    pointer.initialize(repeating: 0, count: count)
    self.count = count
  }

  init(
    copying words: ContiguousArray<UInt32>,
    count: Int
  ) {
    self.init(count: count)
    var index = 0
    while index < count {
      pointer[index] = index < words.count ? words[index] : 0
      index += 1
    }
  }

  borrowing func word(at index: Int) -> UInt32 {
    precondition(index >= 0 && index < count)
    return pointer[index]
  }

  mutating func setWord(_ word: UInt32, at index: Int) {
    precondition(index >= 0 && index < count)
    pointer[index] = word
  }

  mutating func addCarry(_ initialCarry: UInt64, at initialIndex: Int) {
    var carry = initialCarry
    var index = initialIndex
    while index < count {
      let value = UInt64(pointer[index]) + carry
      pointer[index] = UInt32(truncatingIfNeeded: value)
      carry = value >> 32
      index += 1
    }
  }

  mutating func select(
    _ candidate: borrowing RSASecretWords,
    mask: UInt32
  ) {
    precondition(candidate.count == count)
    var index = 0
    while index < count {
      let current = pointer[index]
      pointer[index] = (current & ~mask) | (candidate.pointer[index] & mask)
      index += 1
    }
  }

  borrowing func encoded(byteCount: Int) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
    var index = 0
    while index < byteCount {
      let wordIndex = index / 4
      if wordIndex < count {
        result[byteCount - 1 - index] = UInt8(
          truncatingIfNeeded: pointer[wordIndex] >> UInt32((index & 3) * 8)
        )
      }
      index += 1
    }
    return result
  }

  deinit {
    SecureWipe.erase(
      UnsafeMutableRawPointer(pointer),
      byteCount: count * MemoryLayout<UInt32>.stride
    )
    pointer.deinitialize(count: count)
    pointer.deallocate()
  }
}
