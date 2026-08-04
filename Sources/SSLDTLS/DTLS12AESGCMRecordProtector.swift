import SSLCore
import SSLCrypto

/// Stateless, ownership-safe DTLS 1.2 AES-GCM record protection.
///
/// The caller owns the epoch/sequence state. The protector therefore remains
/// stateless and can be shared only when the caller deliberately serializes
/// sequence allocation, without an internal lock on the crypto hot path. Input
/// record bytes are borrowed; exactly one output allocation is made for each
/// seal/open.
///
/// Unsafe boundary invariants: `SecretBytes` owns and wipes key material; every
/// pointer derived from a key, input span, or output buffer is used only inside
/// its borrow closure; output storage is initialized before `OwnedBytes` consumes
/// it; all nonce, AAD, and output ranges are validated before pointer arithmetic;
/// no pointer or borrowed view escapes a call, and the class has no mutable
/// sequence state to race across `Sendable` callers.
public final class DTLS12AESGCMRecordProtector: Sendable {
  public static let fixedIVByteCount = 4
  public static let explicitNonceByteCount = 8
  public static let tagByteCount = AESGCM.tagByteCount
  public static let maximumPlaintextByteCount = DTLS12WebRTCProfile.maximumPlaintextByteCount

  private let key: SecretBytes
  private let fixedIV: SecretBytes
  public let epoch: UInt16

  public init(
    key: Span<UInt8>,
    fixedIV: Span<UInt8>,
    epoch: UInt16
  ) throws(DTLS12RecordError) {
    guard key.count == 16 || key.count == 32 else {
      throw .invalidKeyLength(actual: key.count)
    }
    guard fixedIV.count == Self.fixedIVByteCount else {
      throw .invalidFixedIVLength(actual: fixedIV.count)
    }
    // The lengths above are positive and below SecretByteCount's hard limit;
    // allocation failure is therefore an internal invariant failure, not a
    // protocol fallback. SecretBytes still owns and wipes both allocations.
    self.key = try! SecretBytes(copying: key)
    self.fixedIV = try! SecretBytes(copying: fixedIV)
    self.epoch = epoch
  }

  public func seal(
    plaintext: Span<UInt8>,
    contentType: UInt8,
    version: UInt16 = DTLS12WebRTCProfile.version,
    sequenceNumber: UInt64
  ) throws(DTLS12RecordError) -> OwnedBytes {
    guard plaintext.count <= Self.maximumPlaintextByteCount else {
      throw .recordTooLarge(actual: plaintext.count)
    }
    guard sequenceNumber <= Self.maximumSequenceNumber else {
      throw .invalidSequenceNumber(sequenceNumber)
    }
    let explicitNonce = Self.makeExplicitNonce(epoch: epoch, sequenceNumber: sequenceNumber)
    let nonce = try explicitNonce.withUnsafeBufferPointer { buffer throws(DTLS12RecordError) in
      try makeNonce(explicitNonce: Span(_unsafeElements: buffer))
    }
    let aad = Self.makeAAD(
      sequenceNumber: sequenceNumber,
      contentType: contentType,
      version: version,
      epoch: epoch,
      plaintextByteCount: plaintext.count
    )
    let outputCount = Self.explicitNonceByteCount + plaintext.count + Self.tagByteCount
    var output = ContiguousArray<UInt8>(repeating: 0, count: outputCount)
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(DTLS12RecordError) in
        guard let base = buffer.baseAddress else { throw .recordTooLarge(actual: 0) }
        var index = 0
        while index < explicitNonce.count {
          base[index] = explicitNonce[index]
          index += 1
        }
        var sealed = MutableSpan(
          _unsafeStart: base.advanced(by: Self.explicitNonceByteCount),
          count: plaintext.count + Self.tagByteCount
        )
        try key.withBorrowedBytes { keyBytes throws(DTLS12RecordError) in
          try nonce.withUnsafeBufferPointer { nonceBuffer throws(DTLS12RecordError) in
            try aad.withUnsafeBufferPointer { aadBuffer throws(DTLS12RecordError) in
              do {
                try AESGCM.seal(
                  key: keyBytes,
                  plaintext: plaintext,
                  authenticatedData: Span(_unsafeElements: aadBuffer),
                  nonce: Span(_unsafeElements: nonceBuffer),
                  into: &sealed
                )
              } catch let error as AEADError {
                throw DTLS12RecordError.aead(error)
              } catch {
                throw DTLS12RecordError.aead(.authenticationFailed)
              }
            }
          }
        }
      }
    } catch let error as DTLS12RecordError {
      throw error
    } catch {
      throw DTLS12RecordError.aead(.authenticationFailed)
    }
    return OwnedBytes(consuming: output)
  }

  public func open(
    recordFragment: Span<UInt8>,
    contentType: UInt8,
    version: UInt16 = DTLS12WebRTCProfile.version
  ) throws(DTLS12RecordError) -> OwnedBytes {
    let minimum = Self.explicitNonceByteCount + Self.tagByteCount
    guard recordFragment.count >= minimum else {
      throw .ciphertextTooShort(actual: recordFragment.count)
    }
    let explicitNonce = recordFragment.extracting(0..<Self.explicitNonceByteCount)
    let receivedEpoch = (UInt16(explicitNonce[0]) << 8) | UInt16(explicitNonce[1])
    guard receivedEpoch == epoch else { throw .invalidEpoch(receivedEpoch) }
    let sequenceNumber = Self.readSequenceNumber(explicitNonce)
    let ciphertextAndTag = recordFragment.extracting(Self.explicitNonceByteCount..<recordFragment.count)
    let plaintextByteCount = ciphertextAndTag.count - Self.tagByteCount
    guard plaintextByteCount <= Self.maximumPlaintextByteCount else {
      throw .recordTooLarge(actual: plaintextByteCount)
    }
    let nonce = try makeNonce(explicitNonce: explicitNonce)
    let aad = Self.makeAAD(
      sequenceNumber: sequenceNumber,
      contentType: contentType,
      version: version,
      epoch: epoch,
      plaintextByteCount: plaintextByteCount
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: plaintextByteCount)
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(DTLS12RecordError) in
        var plaintext = MutableSpan(_unsafeElements: buffer)
        try key.withBorrowedBytes { keyBytes throws(DTLS12RecordError) in
          try nonce.withUnsafeBufferPointer { nonceBuffer throws(DTLS12RecordError) in
            try aad.withUnsafeBufferPointer { aadBuffer throws(DTLS12RecordError) in
              do {
                try AESGCM.open(
                  key: keyBytes,
                  ciphertextAndTag: ciphertextAndTag,
                  authenticatedData: Span(_unsafeElements: aadBuffer),
                  nonce: Span(_unsafeElements: nonceBuffer),
                  into: &plaintext
                )
              } catch let error as AEADError {
                throw DTLS12RecordError.aead(error)
              } catch {
                throw DTLS12RecordError.aead(.authenticationFailed)
              }
            }
          }
        }
      }
    } catch let error as DTLS12RecordError {
      throw error
    } catch {
      throw DTLS12RecordError.aead(.authenticationFailed)
    }
    return OwnedBytes(consuming: output)
  }

  /// Seals a record fragment when the caller already owns the DTLS header
  /// fields. This is the migration seam for sans-IO engines: the engine keeps
  /// sequence/replay state, while this owner keeps only key material and the
  /// AEAD operation. The input spans are borrowed and one output allocation is
  /// returned; no intermediate `[UInt8]` payload is created by this method.
  public func sealRaw(
    plaintext: Span<UInt8>,
    explicitNonce: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(DTLS12RecordError) -> OwnedBytes {
    guard explicitNonce.count == Self.explicitNonceByteCount else {
      throw .invalidExplicitNonceLength(actual: explicitNonce.count)
    }
    guard plaintext.count <= Self.maximumPlaintextByteCount else {
      throw .recordTooLarge(actual: plaintext.count)
    }
    let nonce = try makeNonce(explicitNonce: explicitNonce)
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: Self.explicitNonceByteCount + plaintext.count + Self.tagByteCount
    )
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(DTLS12RecordError) in
        guard let base = buffer.baseAddress else { throw .recordTooLarge(actual: 0) }
        var index = 0
        while index < explicitNonce.count {
          base[index] = explicitNonce[index]
          index += 1
        }
        var sealed = MutableSpan(
          _unsafeStart: base.advanced(by: Self.explicitNonceByteCount),
          count: plaintext.count + Self.tagByteCount
        )
        try key.withBorrowedBytes { keyBytes throws(DTLS12RecordError) in
          try nonce.withUnsafeBufferPointer { nonceBuffer throws(DTLS12RecordError) in
            try authenticatedData.withUnsafeBufferPointer { aadBuffer throws(DTLS12RecordError) in
              do {
                try AESGCM.seal(
                  key: keyBytes,
                  plaintext: plaintext,
                  authenticatedData: Span(_unsafeElements: aadBuffer),
                  nonce: Span(_unsafeElements: nonceBuffer),
                  into: &sealed
                )
              } catch let error as AEADError {
                throw DTLS12RecordError.aead(error)
              } catch {
                throw DTLS12RecordError.aead(.authenticationFailed)
              }
            }
          }
        }
      }
    } catch let error as DTLS12RecordError {
      throw error
    } catch {
      throw DTLS12RecordError.aead(.authenticationFailed)
    }
    return OwnedBytes(consuming: output)
  }

  /// Opens a record fragment when the sans-IO engine has already constructed
  /// the authenticated-data bytes. Authentication failure is surfaced as a
  /// typed error; no plaintext is returned on failure.
  public func openRaw(
    recordFragment: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(DTLS12RecordError) -> OwnedBytes {
    let minimum = Self.explicitNonceByteCount + Self.tagByteCount
    guard recordFragment.count >= minimum else {
      throw .ciphertextTooShort(actual: recordFragment.count)
    }
    let explicitNonce = recordFragment.extracting(0..<Self.explicitNonceByteCount)
    let ciphertextAndTag = recordFragment.extracting(Self.explicitNonceByteCount..<recordFragment.count)
    let plaintextByteCount = ciphertextAndTag.count - Self.tagByteCount
    guard plaintextByteCount <= Self.maximumPlaintextByteCount else {
      throw .recordTooLarge(actual: plaintextByteCount)
    }
    let nonce = try makeNonce(explicitNonce: explicitNonce)
    var output = ContiguousArray<UInt8>(repeating: 0, count: plaintextByteCount)
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(DTLS12RecordError) in
        var plaintext = MutableSpan(_unsafeElements: buffer)
        try key.withBorrowedBytes { keyBytes throws(DTLS12RecordError) in
          try nonce.withUnsafeBufferPointer { nonceBuffer throws(DTLS12RecordError) in
            try authenticatedData.withUnsafeBufferPointer { aadBuffer throws(DTLS12RecordError) in
              do {
                try AESGCM.open(
                  key: keyBytes,
                  ciphertextAndTag: ciphertextAndTag,
                  authenticatedData: Span(_unsafeElements: aadBuffer),
                  nonce: Span(_unsafeElements: nonceBuffer),
                  into: &plaintext
                )
              } catch let error as AEADError {
                throw DTLS12RecordError.aead(error)
              } catch {
                throw DTLS12RecordError.aead(.authenticationFailed)
              }
            }
          }
        }
      }
    } catch let error as DTLS12RecordError {
      throw error
    } catch {
      throw DTLS12RecordError.aead(.authenticationFailed)
    }
    return OwnedBytes(consuming: output)
  }

  private static let maximumSequenceNumber: UInt64 = 0x0000_FFFF_FFFF_FFFF

  private func makeNonce(explicitNonce: Span<UInt8>) throws(DTLS12RecordError) -> ContiguousArray<UInt8> {
    guard explicitNonce.count == Self.explicitNonceByteCount else {
      throw .invalidExplicitNonceLength(actual: explicitNonce.count)
    }
    var nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    fixedIV.withBorrowedBytes { iv in
      var index = 0
      while index < iv.count { nonce[index] = iv[index]; index += 1 }
    }
    var index = 0
    while index < explicitNonce.count {
      nonce[Self.fixedIVByteCount + index] = explicitNonce[index]
      index += 1
    }
    return nonce
  }

  private static func makeExplicitNonce(epoch: UInt16, sequenceNumber: UInt64) -> ContiguousArray<UInt8> {
    var nonce = ContiguousArray<UInt8>(repeating: 0, count: Self.explicitNonceByteCount)
    nonce[0] = UInt8(truncatingIfNeeded: epoch >> 8)
    nonce[1] = UInt8(truncatingIfNeeded: epoch)
    var index = 0
    while index < 6 {
      nonce[2 + index] = UInt8(truncatingIfNeeded: sequenceNumber >> UInt64(40 - index * 8))
      index += 1
    }
    return nonce
  }

  private static func readSequenceNumber(_ explicitNonce: Span<UInt8>) -> UInt64 {
    var result: UInt64 = 0
    var index = 2
    while index < 8 {
      result = (result << 8) | UInt64(explicitNonce[index])
      index += 1
    }
    return result
  }

  private static func makeAAD(
    sequenceNumber: UInt64,
    contentType: UInt8,
    version: UInt16,
    epoch: UInt16,
    plaintextByteCount: Int
  ) -> ContiguousArray<UInt8> {
    var aad = ContiguousArray<UInt8>(repeating: 0, count: 13)
    aad[0] = UInt8(truncatingIfNeeded: epoch >> 8)
    aad[1] = UInt8(truncatingIfNeeded: epoch)
    var index = 0
    while index < 6 {
      aad[2 + index] = UInt8(truncatingIfNeeded: sequenceNumber >> UInt64(40 - index * 8))
      index += 1
    }
    aad[8] = contentType
    aad[9] = UInt8(truncatingIfNeeded: version >> 8)
    aad[10] = UInt8(truncatingIfNeeded: version)
    aad[11] = UInt8(truncatingIfNeeded: UInt16(plaintextByteCount) >> 8)
    aad[12] = UInt8(truncatingIfNeeded: UInt16(plaintextByteCount))
    return aad
  }
}

public enum DTLS12RecordError: Error, Sendable, Equatable {
  case invalidKeyLength(actual: Int)
  case invalidFixedIVLength(actual: Int)
  case invalidExplicitNonceLength(actual: Int)
  case invalidEpoch(UInt16)
  case invalidSequenceNumber(UInt64)
  case recordTooLarge(actual: Int)
  case ciphertextTooShort(actual: Int)
  case aead(AEADError)
}
