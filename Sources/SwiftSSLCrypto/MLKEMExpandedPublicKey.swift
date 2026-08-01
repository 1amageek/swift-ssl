import SwiftSSLCore

/// Immutable, decoded ML-KEM public-key material used by encapsulation.
final class MLKEMExpandedPublicKey {
  private let vector: MLKEMPolynomialStorage
  private let matrix: MLKEMPolynomialStorage
  private let publicKeyHash: UnsafeMutablePointer<UInt8>
  let dimension: Int

  // Unsafe ownership invariants:
  // - Construction consumes the unique polynomial owners after decoding.
  // - No mutation API is exposed after publication.
  // - Every coefficient access is a scoped immutable borrow from retained storage.
  // - The 32-byte hash allocation is initialized before publication.
  // - Its pointer never escapes; callers receive only a scoped immutable Span.
  // - ARC retains all owners for each borrow and releases them exactly once.
  init(
    consumingVector vector: consuming MLKEMPolynomialStorage,
    matrix: consuming MLKEMPolynomialStorage,
    publicKeyHash: Span<UInt8>,
    dimension: Int
  ) {
    precondition(vector.polynomialCount == dimension)
    precondition(matrix.polynomialCount == dimension * dimension)
    precondition(publicKeyHash.count == 32)
    self.vector = vector
    self.matrix = matrix
    let hashPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
    hashPointer.initialize(repeating: 0, count: 32)
    var hashIndex = 0
    while hashIndex < 32 {
      hashPointer[hashIndex] = publicKeyHash[hashIndex]
      hashIndex += 1
    }
    self.publicKeyHash = hashPointer
    self.dimension = dimension
  }

  @inline(__always)
  borrowing func withHash<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    let buffer = UnsafeBufferPointer(start: publicKeyHash, count: 32)
    return try body(Span(_unsafeElements: buffer))
  }

  @inline(__always)
  borrowing func withVectorPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<MLKEMArithmetic.Coefficient>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < dimension)
    return try vector.withPolynomial(at: index, body)
  }

  @inline(__always)
  borrowing func withMatrixPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<MLKEMArithmetic.Coefficient>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < dimension * dimension)
    return try matrix.withPolynomial(at: index, body)
  }

  deinit {
    publicKeyHash.deinitialize(count: 32)
    publicKeyHash.deallocate()
  }
}

// Polynomial storage is uniquely owned, fully initialized before publication,
// and reachable only through immutable scoped borrows after construction.
extension MLKEMExpandedPublicKey: @unchecked Sendable {}
