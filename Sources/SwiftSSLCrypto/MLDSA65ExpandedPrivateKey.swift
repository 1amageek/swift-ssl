import SwiftSSLCore

/// Immutable expanded secret coefficients retained by an ML-DSA-65 private key.
final class MLDSA65ExpandedPrivateKey {
  private static let s1CoefficientCount = 5 * 256
  private static let s2CoefficientCount = 6 * 256
  private static let t0CoefficientCount = 6 * 256
  private let key: SecretBytes
  private var s1NTT: ContiguousArray<UInt32>
  private var s2NTT: ContiguousArray<UInt32>
  private var t0NTT: ContiguousArray<UInt32>

  // Unsafe ownership invariants:
  // - this object uniquely owns three initialized contiguous coefficient buffers;
  // - all inputs have exact validated lengths and contain NTT-domain values;
  // - every pointer borrow is synchronous, immutable, and cannot escape;
  // - deinit volatile-erases every secret byte before exactly-once release;
  // - no mutable or Sendable-crossing pointer is published.
  init(
    key: Span<UInt8>,
    s1NTT: Span<UInt32>,
    s2NTT: Span<UInt32>,
    t0NTT: Span<UInt32>
  ) throws(MLDSAError) {
    precondition(key.count == 32)
    precondition(s1NTT.count == Self.s1CoefficientCount)
    precondition(s2NTT.count == Self.s2CoefficientCount)
    precondition(t0NTT.count == Self.t0CoefficientCount)
    do {
      self.key = try SecretBytes(copying: key)
    } catch {
      throw .secretMemory(error)
    }
    var copiedS1 = ContiguousArray<UInt32>()
    copiedS1.reserveCapacity(Self.s1CoefficientCount)
    var index = 0
    while index < s1NTT.count {
      copiedS1.append(s1NTT[index])
      index += 1
    }
    var copiedS2 = ContiguousArray<UInt32>()
    copiedS2.reserveCapacity(Self.s2CoefficientCount)
    index = 0
    while index < s2NTT.count {
      copiedS2.append(s2NTT[index])
      index += 1
    }
    var copiedT0 = ContiguousArray<UInt32>()
    copiedT0.reserveCapacity(Self.t0CoefficientCount)
    index = 0
    while index < t0NTT.count {
      copiedT0.append(t0NTT[index])
      index += 1
    }
    self.s1NTT = copiedS1
    self.s2NTT = copiedS2
    self.t0NTT = copiedT0
  }

  init(
    key: consuming SecretBytes,
    takingS1NTT s1NTT: inout ContiguousArray<UInt32>,
    takingS2NTT s2NTT: inout ContiguousArray<UInt32>,
    takingT0NTT t0NTT: inout ContiguousArray<UInt32>
  ) {
    precondition(s1NTT.count == Self.s1CoefficientCount)
    precondition(s2NTT.count == Self.s2CoefficientCount)
    precondition(t0NTT.count == Self.t0CoefficientCount)
    self.key = consume key
    self.s1NTT = s1NTT
    self.s2NTT = s2NTT
    self.t0NTT = t0NTT

    // Transferring the three uniquely referenced array owners avoids copying
    // 17 polynomials. Clearing each source only releases its reference; this
    // owner retains and eventually wipes the original allocation exactly once.
    s1NTT = []
    s2NTT = []
    t0NTT = []
  }

  borrowing func withKey<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try key.withBorrowedBytes(body)
  }

  borrowing func withMaterial<Result, Failure: Error>(
    _ body: (
      Span<UInt8>,
      UnsafePointer<UInt32>,
      UnsafePointer<UInt32>,
      UnsafePointer<UInt32>
    ) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try key.withBorrowedBytes { keyBytes throws(Failure) in
      try s1NTT.withUnsafeBufferPointer { s1Buffer throws(Failure) in
        try s2NTT.withUnsafeBufferPointer { s2Buffer throws(Failure) in
          try t0NTT.withUnsafeBufferPointer { t0Buffer throws(Failure) in
            try body(
              keyBytes,
              s1Buffer.baseAddress.unsafelyUnwrapped,
              s2Buffer.baseAddress.unsafelyUnwrapped,
              t0Buffer.baseAddress.unsafelyUnwrapped
            )
          }
        }
      }
    }
  }

  deinit {
    Self.erase(&s1NTT)
    Self.erase(&s2NTT)
    Self.erase(&t0NTT)
  }

  private static func erase(_ coefficients: inout ContiguousArray<UInt32>) {
    coefficients.withUnsafeMutableBufferPointer { buffer in
      guard let pointer = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(pointer),
        byteCount: buffer.count * MemoryLayout<UInt32>.stride
      )
    }
  }
}

// Construction publishes no mutation API. The retained arrays are uniquely
// owned after initialization, scoped immutable borrows retain the owner, and
// destruction erases all storage before releasing it exactly once.
extension MLDSA65ExpandedPrivateKey: @unchecked Sendable {}
