import SwiftSSLCore

/// Unique storage for one or more ML-KEM polynomials.
struct MLKEMPolynomialStorage: ~Copyable {
  static let coefficientCount = 256

  enum Sensitivity {
    case publicData
    case secret
  }

  private let pointer: UnsafeMutablePointer<UInt16>
  private let sensitivity: Sensitivity
  let polynomialCount: Int

  // Unsafe boundary invariants:
  // - This value uniquely owns polynomialCount * 256 initialized UInt16 values.
  // - The multiplication is checked before allocation and cannot overflow.
  // - Raw allocation uses UInt64 alignment before a one-time UInt16 binding.
  // - Every scoped borrow is range checked and no pointer or Span can escape.
  // - No rebind or overlapping mutable alias is created after initialization.
  // - No Sendable boundary is crossed; this internal owner is deliberately non-Sendable.
  // - Secret storage is volatile-erased before exactly-once deallocation;
  //   public storage is deinitialized and deallocated without a redundant wipe.
  init(polynomialCount: Int, sensitivity: Sensitivity) {
    precondition(polynomialCount > 0)
    let (coefficientCount, overflow) = polynomialCount.multipliedReportingOverflow(
      by: Self.coefficientCount
    )
    precondition(!overflow)
    let (byteCount, byteCountOverflow) = coefficientCount.multipliedReportingOverflow(
      by: MemoryLayout<UInt16>.stride
    )
    precondition(!byteCountOverflow)
    let allocation = UnsafeMutableRawPointer.allocate(
      byteCount: byteCount,
      alignment: MemoryLayout<UInt64>.alignment
    )
    pointer = allocation.bindMemory(to: UInt16.self, capacity: coefficientCount)
    pointer.initialize(repeating: 0, count: coefficientCount)
    self.polynomialCount = polynomialCount
    self.sensitivity = sensitivity
  }

  @inline(__always)
  borrowing func withPolynomial<Result: ~Copyable, Failure: Error>(
    at index: Int,
    _ body: (Span<UInt16>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < polynomialCount)
    let start = pointer.advanced(by: index * Self.coefficientCount)
    let buffer = UnsafeBufferPointer(start: start, count: Self.coefficientCount)
    return try body(Span(_unsafeElements: buffer))
  }

  @inline(__always)
  mutating func withMutablePolynomial<Result, Failure: Error>(
    at index: Int,
    _ body: (inout MutableSpan<UInt16>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index < polynomialCount)
    let start = pointer.advanced(by: index * Self.coefficientCount)
    var span = MutableSpan(_unsafeStart: start, count: Self.coefficientCount)
    return try body(&span)
  }

  // Unsafe boundary invariants:
  // - Both polynomial ranges are initialized, in bounds, and disjoint.
  // - Each MutableSpan is scoped to body and no derived pointer can escape.
  // - This unique owner remains exclusively borrowed for the complete call.
  @inline(__always)
  mutating func withTwoMutablePolynomials<Result, Failure: Error>(
    startingAt index: Int,
    _ body: (
      inout MutableSpan<UInt16>,
      inout MutableSpan<UInt16>
    ) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    precondition(index >= 0 && index + 2 <= polynomialCount)
    let stride = Self.coefficientCount
    var first = MutableSpan(_unsafeStart: pointer.advanced(by: index * stride), count: stride)
    var second = MutableSpan(
      _unsafeStart: pointer.advanced(by: (index + 1) * stride),
      count: stride
    )
    return try body(&first, &second)
  }

  deinit {
    let coefficientCount = polynomialCount * Self.coefficientCount
    switch sensitivity {
    case .secret:
      precondition(coefficientCount.isMultiple(of: 4))
      SecureWipe.eraseUInt64Words(
        UnsafeMutableRawPointer(pointer),
        wordCount: coefficientCount / 4
      )
    case .publicData:
      break
    }
    pointer.deinitialize(count: coefficientCount)
    pointer.deallocate()
  }
}
