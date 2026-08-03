import SwiftSSLCore

/// Uniquely owned RSA private exponent for RSA-PSS signing.
public struct RSAPrivateKey: ~Copyable, Sendable {
  private static let maximumPKCS1DERByteCount = 8 * 1024

  public let publicKey: RSAPublicKey
  private let privateExponent: SecretBytes

  /// Parses a canonical two-prime PKCS #1 `RSAPrivateKey` document.
  ///
  /// The modulus is checked against the encoded primes. CRT parameters are
  /// parsed canonically but are not retained because signing uses the
  /// fixed-loop full-exponent path rather than a CRT implementation.
  public init(pkcs1DER: Span<UInt8>) throws(RSAKeyError) {
    guard pkcs1DER.count <= Self.maximumPKCS1DERByteCount else {
      throw .crypto(
        .invalidLength(
          expected: Self.maximumPKCS1DERByteCount,
          actual: pkcs1DER.count
        )
      )
    }
    var offset = 0
    let modulusRange: Range<Int>
    let publicExponentRange: Range<Int>
    let privateExponentRange: Range<Int>
    let prime1Range: Range<Int>
    let prime2Range: Range<Int>
    do {
      guard Self.readByte(pkcs1DER, at: &offset) == 0x30 else {
        throw CryptoInputError.nonCanonicalEncoding
      }
      let sequenceByteCount = try Self.readDERLength(pkcs1DER, at: &offset)
      guard sequenceByteCount == pkcs1DER.count - offset else {
        throw CryptoInputError.nonCanonicalEncoding
      }
      let versionRange = try Self.readPositiveIntegerRange(
        pkcs1DER,
        at: &offset
      )
      guard versionRange.count == 1, pkcs1DER[versionRange.lowerBound] == 0 else {
        throw CryptoInputError.nonCanonicalEncoding
      }
      modulusRange = try Self.readPositiveIntegerRange(pkcs1DER, at: &offset)
      publicExponentRange = try Self.readPositiveIntegerRange(
        pkcs1DER,
        at: &offset
      )
      privateExponentRange = try Self.readPositiveIntegerRange(
        pkcs1DER,
        at: &offset
      )
      prime1Range = try Self.readPositiveIntegerRange(pkcs1DER, at: &offset)
      prime2Range = try Self.readPositiveIntegerRange(pkcs1DER, at: &offset)
      var remainingInteger = 0
      while remainingInteger < 3 {
        _ = try Self.readPositiveIntegerRange(pkcs1DER, at: &offset)
        remainingInteger += 1
      }
      guard offset == pkcs1DER.count,
        publicExponentRange.count <= MemoryLayout<UInt64>.size,
        prime1Range.count <= modulusRange.count,
        prime2Range.count <= modulusRange.count,
        Self.isNontrivialOddInteger(pkcs1DER, range: prime1Range),
        Self.isNontrivialOddInteger(pkcs1DER, range: prime2Range)
      else {
        throw CryptoInputError.nonCanonicalEncoding
      }
    } catch let error as CryptoInputError {
      throw .crypto(error)
    } catch {
      throw .crypto(.nonCanonicalEncoding)
    }

    var publicExponent: UInt64 = 0
    var index = publicExponentRange.lowerBound
    while index < publicExponentRange.upperBound {
      publicExponent = (publicExponent << 8) | UInt64(pkcs1DER[index])
      index += 1
    }
    let modulus = RSAUInt(bytes: pkcs1DER.extracting(modulusRange))
    let primeProduct = RSAUInt.multiply(
      RSAUInt(bytes: pkcs1DER.extracting(prime1Range)),
      RSAUInt(bytes: pkcs1DER.extracting(prime2Range))
    )
    guard !(primeProduct < modulus), !(modulus < primeProduct) else {
      throw .invalidKeyRelation
    }
    try self.init(
      modulus: pkcs1DER.extracting(modulusRange),
      publicExponent: publicExponent,
      privateExponent: pkcs1DER.extracting(privateExponentRange)
    )
  }

  public init(
    modulus: Span<UInt8>,
    publicExponent: UInt64,
    privateExponent: Span<UInt8>
  ) throws(RSAKeyError) {
    let publicKey: RSAPublicKey
    do {
      publicKey = try RSAPublicKey(
        modulus: modulus,
        exponent: publicExponent
      )
    } catch let error {
      throw .crypto(error)
    }
    guard !privateExponent.isEmpty,
      privateExponent.count <= modulus.count,
      privateExponent[0] != 0,
      privateExponent[privateExponent.count - 1] & 1 == 1
    else {
      throw .crypto(.nonCanonicalEncoding)
    }
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(modulus.count)
    } catch let error {
      throw .secretMemory(error)
    }
    let exponent = SecretBytes(byteCount: byteCount) { destination in
      let padding = modulus.count - privateExponent.count
      var index = 0
      while index < privateExponent.count {
        destination[padding + index] = privateExponent[index]
        index += 1
      }
    }
    let matches = publicKey.withModulusBytes { modulusBytes in
      exponent.withBorrowedBytes { exponentBytes in
        RSAUInt.privateExponentMatches(
          exponentBytes,
          publicExponent: publicExponent,
          modulus: RSAUInt(bytes: modulusBytes)
        )
      }
    }
    guard matches else { throw .invalidKeyRelation }
    self.publicKey = publicKey
    self.privateExponent = exponent
  }

  borrowing func withPrivateExponent<Result: ~Copyable>(
    _ body: (Span<UInt8>) -> Result
  ) -> Result {
    privateExponent.withBorrowedBytes(body)
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

  private static func readPositiveIntegerRange(
    _ bytes: Span<UInt8>,
    at offset: inout Int
  ) throws(CryptoInputError) -> Range<Int> {
    guard readByte(bytes, at: &offset) == 0x02 else {
      throw .nonCanonicalEncoding
    }
    let byteCount = try readDERLength(bytes, at: &offset)
    guard byteCount > 0, offset <= bytes.count - byteCount else {
      throw .nonCanonicalEncoding
    }
    let encodedStart = offset
    offset += byteCount
    guard bytes[encodedStart] & 0x80 == 0 else {
      throw .nonCanonicalEncoding
    }
    if bytes[encodedStart] == 0 {
      guard byteCount == 1 || bytes[encodedStart + 1] & 0x80 != 0 else {
        throw .nonCanonicalEncoding
      }
      if byteCount > 1 {
        return (encodedStart + 1)..<(encodedStart + byteCount)
      }
    }
    return encodedStart..<(encodedStart + byteCount)
  }

  private static func isNontrivialOddInteger(
    _ bytes: Span<UInt8>,
    range: Range<Int>
  ) -> Bool {
    guard !range.isEmpty else { return false }
    if range.count == 1, bytes[range.lowerBound] <= 1 { return false }
    return bytes[range.upperBound - 1] & 1 == 1
  }
}
