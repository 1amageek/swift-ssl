/// Immutable NTT-domain public coefficients cached after first use.
final class MLDSA65ExpandedPublicMaterial {
  static let t1CoefficientCount = 6 * 256
  static let matrixCoefficientCount = 6 * 5 * 256
  private static let coefficientCount =
    t1CoefficientCount + matrixCoefficientCount

  private let coefficients: UnsafeMutablePointer<UInt32>

  // Unsafe ownership invariants:
  // - this object uniquely owns coefficientCount initialized UInt32 values;
  // - validated t1 and matrix inputs are copied into disjoint bounded regions;
  // - published pointers are immutable and scoped to a nonescaping closure;
  // - pointers never cross a mutation or Sendable boundary;
  // - deinit releases the initialized allocation exactly once.
  init(t1NTT: Span<UInt32>, matrix: Span<UInt32>) {
    precondition(t1NTT.count == Self.t1CoefficientCount)
    precondition(matrix.count == Self.matrixCoefficientCount)
    let coefficients = UnsafeMutablePointer<UInt32>.allocate(
      capacity: Self.coefficientCount
    )
    coefficients.initialize(repeating: 0, count: Self.coefficientCount)
    var index = 0
    while index < t1NTT.count {
      coefficients[index] = t1NTT[index]
      index += 1
    }
    index = 0
    while index < matrix.count {
      coefficients[Self.t1CoefficientCount + index] = matrix[index]
      index += 1
    }
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
      UnsafePointer(coefficients.advanced(by: Self.t1CoefficientCount))
    )
  }

  deinit {
    coefficients.deinitialize(count: Self.coefficientCount)
    coefficients.deallocate()
  }
}

// The backing coefficients are immutable after initialization. Every pointer
// borrow is scoped and ARC retains the owner for the complete borrow.
extension MLDSA65ExpandedPublicMaterial: @unchecked Sendable {}
