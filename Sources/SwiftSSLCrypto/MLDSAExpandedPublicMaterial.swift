/// Immutable NTT-domain public coefficients cached after first use.
final class MLDSAExpandedPublicMaterial {
  private let t1CoefficientCount: Int
  private let coefficientCount: Int
  private let coefficients: UnsafeMutablePointer<UInt32>

  // Unsafe ownership invariants:
  // - this object uniquely owns coefficientCount initialized UInt32 values;
  // - validated t1 and matrix inputs are copied into disjoint bounded regions;
  // - published pointers are immutable and scoped to a nonescaping closure;
  // - pointers never cross a mutation or Sendable boundary;
  // - deinit releases the initialized allocation exactly once.
  init(
    parameterSet: MLDSAParameterSet,
    t1NTT: Span<UInt32>,
    matrix: Span<UInt32>
  ) {
    let t1CoefficientCount = parameterSet.k * 256
    let matrixCoefficientCount = parameterSet.k * parameterSet.l * 256
    let coefficientCount = t1CoefficientCount + matrixCoefficientCount
    precondition(t1NTT.count == t1CoefficientCount)
    precondition(matrix.count == matrixCoefficientCount)
    let coefficients = UnsafeMutablePointer<UInt32>.allocate(
      capacity: coefficientCount
    )
    coefficients.initialize(repeating: 0, count: coefficientCount)
    var index = 0
    while index < t1NTT.count {
      coefficients[index] = t1NTT[index]
      index += 1
    }
    index = 0
    while index < matrix.count {
      coefficients[t1CoefficientCount + index] = matrix[index]
      index += 1
    }
    self.t1CoefficientCount = t1CoefficientCount
    self.coefficientCount = coefficientCount
    self.coefficients = coefficients
  }

  borrowing func withMaterial<Result: ~Copyable, Failure: Error>(
    _ body: (
      UnsafePointer<UInt32>,
      UnsafePointer<UInt32>
    ) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(
      UnsafePointer(coefficients),
      UnsafePointer(coefficients.advanced(by: t1CoefficientCount))
    )
  }

  deinit {
    coefficients.deinitialize(count: coefficientCount)
    coefficients.deallocate()
  }
}

// The backing coefficients are immutable after initialization. Every pointer
// borrow is scoped and ARC retains the owner for the complete borrow.
extension MLDSAExpandedPublicMaterial: @unchecked Sendable {}
