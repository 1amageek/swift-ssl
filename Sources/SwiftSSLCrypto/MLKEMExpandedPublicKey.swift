/// Immutable, decoded ML-KEM public-key material used by encapsulation.
struct MLKEMExpandedPublicKey: Sendable {
  private let vector: ContiguousArray<MLKEMArithmetic.Coefficient>
  private let matrix: ContiguousArray<MLKEMArithmetic.Coefficient>
  private let publicKeyHash: ContiguousArray<UInt8>
  let dimension: Int

  init(
    copyingVector vector: borrowing MLKEMPolynomialStorage,
    matrix: borrowing MLKEMPolynomialStorage,
    publicKeyHash: Span<UInt8>,
    dimension: Int
  ) {
    precondition(vector.polynomialCount == dimension)
    precondition(matrix.polynomialCount == dimension * dimension)
    precondition(publicKeyHash.count == 32)
    self.vector = Self.copy(vector)
    self.matrix = Self.copy(matrix)
    self.publicKeyHash = Self.copy(publicKeyHash)
    self.dimension = dimension
  }

  @inline(__always)
  var hashSpan: Span<UInt8> {
    @_lifetime(borrow self)
    borrowing get {
      publicKeyHash.span
    }
  }

  @inline(__always)
  borrowing func withVectorPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<MLKEMArithmetic.Coefficient>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < dimension)
    let start = index * MLKEMPolynomialStorage.coefficientCount
    return try body(
      vector.span.extracting(
        start..<(start + MLKEMPolynomialStorage.coefficientCount)
      )
    )
  }

  @inline(__always)
  borrowing func withMatrixPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<MLKEMArithmetic.Coefficient>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < dimension * dimension)
    let start = index * MLKEMPolynomialStorage.coefficientCount
    return try body(
      matrix.span.extracting(
        start..<(start + MLKEMPolynomialStorage.coefficientCount)
      )
    )
  }

  private static func copy(
    _ source: borrowing MLKEMPolynomialStorage
  ) -> ContiguousArray<MLKEMArithmetic.Coefficient> {
    var result = ContiguousArray<MLKEMArithmetic.Coefficient>(
      repeating: 0,
      count: source.polynomialCount * MLKEMPolynomialStorage.coefficientCount
    )
    var destination = result.mutableSpan
    var polynomialIndex = 0
    while polynomialIndex < source.polynomialCount {
      source.withPolynomial(at: polynomialIndex) { polynomial in
        let destinationOffset =
          polynomialIndex * MLKEMPolynomialStorage.coefficientCount
        var coefficientIndex = 0
        while coefficientIndex < MLKEMPolynomialStorage.coefficientCount {
          destination[destinationOffset + coefficientIndex] = polynomial[coefficientIndex]
          coefficientIndex += 1
        }
      }
      polynomialIndex += 1
    }
    return result
  }

  private static func copy(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(source.count)
    var index = 0
    while index < source.count {
      result.append(source[index])
      index += 1
    }
    return result
  }
}
