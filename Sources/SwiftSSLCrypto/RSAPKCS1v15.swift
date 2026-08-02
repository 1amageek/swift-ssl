import SwiftSSLCore

/// EMSA-PKCS1-v1_5 verification for RSA public keys.
///
/// This surface is deliberately verification-only. It accepts only SHA-2
/// DigestInfo encodings and requires the complete recovered encoded message to
/// match the canonical DER form from RFC 8017.
public enum RSAPKCS1v15 {
  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    publicKey: borrowing RSAPublicKey,
    hash: RSAPKCS1v15Hash
  ) throws(CryptoInputError) -> Bool {
    let modulusByteCount = publicKey.modulusByteCount
    guard signature.count == modulusByteCount else {
      throw .invalidLength(expected: modulusByteCount, actual: signature.count)
    }
    guard messageHash.count == hash.digestByteCount else {
      throw .invalidLength(expected: hash.digestByteCount, actual: messageHash.count)
    }

    let modulus = publicKey.withModulusBytes { bytes in
      RSAUInt(bytes: bytes)
    }
    let encoded = RSAUInt(bytes: signature)
    guard encoded < modulus else { throw .nonCanonicalEncoding }

    let recovered = RSAUInt.modularPower(
      encoded,
      exponent: publicKey.exponent,
      modulus: modulus
    ).encoded(byteCount: modulusByteCount)
    return verifyEncodedMessage(
      recovered.span,
      messageHash: messageHash,
      hash: hash
    )
  }

  private static func verifyEncodedMessage(
    _ encodedMessage: Span<UInt8>,
    messageHash: Span<UInt8>,
    hash: RSAPKCS1v15Hash
  ) -> Bool {
    let digestInfoByteCount = hash.digestInfoPrefixByteCount + messageHash.count
    let paddingByteCount = encodedMessage.count - digestInfoByteCount - 3
    guard paddingByteCount >= 8,
      encodedMessage[0] == 0,
      encodedMessage[1] == 1
    else {
      return false
    }

    var index = 0
    while index < paddingByteCount {
      guard encodedMessage[2 + index] == 0xFF else { return false }
      index += 1
    }
    let separatorIndex = 2 + paddingByteCount
    guard encodedMessage[separatorIndex] == 0 else { return false }

    let digestInfoIndex = separatorIndex + 1
    index = 0
    while index < hash.digestInfoPrefixByteCount {
      guard encodedMessage[digestInfoIndex + index] == hash.digestInfoPrefixByte(at: index) else {
        return false
      }
      index += 1
    }

    let recoveredHash = encodedMessage.extracting(
      (digestInfoIndex + hash.digestInfoPrefixByteCount)..<encodedMessage.count
    )
    return ConstantTime.equal(recoveredHash, messageHash)
  }
}
