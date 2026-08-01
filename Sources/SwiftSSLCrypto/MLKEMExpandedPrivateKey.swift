import SwiftSSLCore

/// Immutable, decoded ML-KEM private-key material used by decapsulation.
final class MLKEMExpandedPrivateKey {
  let publicKey: MLKEMExpandedPublicKey
  private let secretVector: MLKEMPolynomialStorage
  private let rejectionValue: SecretBytes
  let dimension: Int

  // Unsafe ownership invariants:
  // - The local polynomial owner is uniquely mutable only during decoding.
  // - Successful initialization consumes that owner without copying secret coefficients.
  // - No mutation API is exposed after publication and all borrows remain scoped.
  // - The polynomial owner and SecretBytes each perform exactly-once volatile erasure.
  init(
    decapsulationKey: Span<UInt8>,
    publicKey: MLKEMExpandedPublicKey,
    parameters: MLKEMParameters
  ) throws(KEMError) {
    precondition(decapsulationKey.count == parameters.decapsulationKeyByteCount)
    precondition(publicKey.dimension == parameters.dimension)
    var secretVector = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .secret
    )

    var index = 0
    while index < parameters.dimension {
      secretVector.withMutablePolynomial(at: index) { polynomial in
        let start = index * 384
        MLKEMArithmetic.decode(
          decapsulationKey.extracting(start..<(start + 384)),
          bitCount: 12,
          into: &polynomial
        )
      }
      index += 1
    }

    let rejectionStart = parameters.decapsulationKeyByteCount - 32
    let rejectionValue: SecretBytes
    do {
      rejectionValue = try SecretBytes(
        copying: decapsulationKey.extracting(rejectionStart..<decapsulationKey.count)
      )
    } catch {
      throw .secretMemory(error)
    }

    self.publicKey = publicKey
    self.secretVector = consume secretVector
    self.rejectionValue = rejectionValue
    dimension = parameters.dimension
  }

  init(
    consumingSecretVector secretVector: consuming MLKEMPolynomialStorage,
    publicKey: MLKEMExpandedPublicKey,
    rejectionValue: Span<UInt8>,
    parameters: MLKEMParameters
  ) throws(KEMError) {
    precondition(secretVector.polynomialCount == parameters.dimension)
    precondition(publicKey.dimension == parameters.dimension)
    precondition(rejectionValue.count == 32)
    let ownedRejectionValue: SecretBytes
    do {
      ownedRejectionValue = try SecretBytes(copying: rejectionValue)
    } catch {
      throw .secretMemory(error)
    }

    self.publicKey = publicKey
    self.secretVector = secretVector
    self.rejectionValue = ownedRejectionValue
    dimension = parameters.dimension
  }

  @inline(__always)
  borrowing func withSecretPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<MLKEMArithmetic.Coefficient>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < dimension)
    return try secretVector.withPolynomial(at: index, body)
  }

  @inline(__always)
  borrowing func withRejectionValue<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try rejectionValue.withBorrowedBytes(body)
  }
}

// Construction consumes unique secret storage, all published access is an
// immutable scoped borrow, and ARC retains the owner until erasure and release.
extension MLKEMExpandedPrivateKey: @unchecked Sendable {}
