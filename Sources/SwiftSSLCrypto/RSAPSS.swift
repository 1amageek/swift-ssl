import SwiftSSLCore

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

  public var modulusByteCount: Int { modulus.count }

  public borrowing func withModulusBytes<Result, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(modulus.span)
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

/// EMSA-PSS verification for RSA public keys.
///
/// This is deliberately a verification-only surface. The public exponent is
/// not secret, while the encoded message and all intermediate buffers remain
/// bounded by the caller-owned modulus size.
public enum RSAPSS {
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
