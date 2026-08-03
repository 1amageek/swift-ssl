import SSLCore
import Synchronization

/// Immutable decoded public key with a synchronized derived-material cache.
final class MLDSAExpandedPublicKey {
  private let parameterSet: MLDSAParameterSet
  private let t1CoefficientCount: Int
  private let bytes: UnsafeMutablePointer<UInt8>
  private let t1: UnsafeMutablePointer<UInt32>
  private let cachedMaterial: Mutex<MLDSAExpandedPublicMaterial?>

  // Unsafe ownership invariants:
  // - this object uniquely owns 96 bytes and t1CoefficientCount initialized words;
  // - encoded, hash, and t1 inputs have exact validated lengths before allocation;
  // - published access is immutable and scoped to a nonescaping closure;
  // - the same Mutex-protected cache contract applies on Native, WASM, and Embedded;
  // - cache construction occurs outside the short critical section and duplicate
  //   concurrent construction is harmless because material is immutable;
  // - pointers never escape and deinit releases both allocations exactly once.
  init(
    parameterSet: MLDSAParameterSet,
    encoded: Span<UInt8>,
    publicKeyHash: Span<UInt8>,
    t1: Span<UInt32>
  ) {
    let t1CoefficientCount = parameterSet.k * 256
    precondition(encoded.count == parameterSet.publicKeyByteCount)
    precondition(publicKeyHash.count == 64)
    precondition(t1.count == t1CoefficientCount)
    let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: 96)
    bytes.initialize(repeating: 0, count: 96)
    var byteIndex = 0
    while byteIndex < 32 {
      bytes[byteIndex] = encoded[byteIndex]
      byteIndex += 1
    }
    byteIndex = 0
    while byteIndex < 64 {
      bytes[32 + byteIndex] = publicKeyHash[byteIndex]
      byteIndex += 1
    }
    self.bytes = bytes
    let storedT1 = UnsafeMutablePointer<UInt32>.allocate(
      capacity: t1CoefficientCount
    )
    storedT1.initialize(repeating: 0, count: t1CoefficientCount)
    var index = 0
    while index < t1.count {
      storedT1[index] = t1[index]
      index += 1
    }
    self.parameterSet = parameterSet
    self.t1CoefficientCount = t1CoefficientCount
    self.t1 = storedT1
    cachedMaterial = Mutex(nil)
  }

  borrowing func withMaterial<Result: ~Copyable>(
    _ body: (
      Span<UInt8>,
      Span<UInt8>,
      UnsafePointer<UInt32>,
      UnsafePointer<UInt32>
    ) throws(MLDSAError) -> Result
  ) throws(MLDSAError) -> Result {
    let rho = Span(
      _unsafeElements: UnsafeBufferPointer(start: bytes, count: 32)
    )
    let publicKeyHash = Span(
      _unsafeElements: UnsafeBufferPointer(
        start: bytes.advanced(by: 32),
        count: 64
      )
    )
    let material: MLDSAExpandedPublicMaterial
    if let existing = cachedMaterial.withLock({ $0 }) {
      material = existing
    } else {
      let t1Span = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: UnsafePointer(t1),
          count: t1CoefficientCount
        )
      )
      let created = try MLDSACore(parameterSet: parameterSet).expandPublicMaterial(
        rho: rho,
        t1: t1Span
      )
      material = cachedMaterial.withLock { state in
        if let existing = state {
          return existing
        }
        state = created
        return created
      }
    }
    return try material.withMaterial { t1NTT, matrix throws(MLDSAError) in
      try body(rho, publicKeyHash, t1NTT, matrix)
    }
  }

  borrowing func withBaseMaterial<Result: ~Copyable, Failure: Error>(
    _ body: (
      Span<UInt8>,
      Span<UInt8>,
      UnsafePointer<UInt32>
    ) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    let rho = Span(
      _unsafeElements: UnsafeBufferPointer(start: bytes, count: 32)
    )
    let publicKeyHash = Span(
      _unsafeElements: UnsafeBufferPointer(
        start: bytes.advanced(by: 32),
        count: 64
      )
    )
    return try body(rho, publicKeyHash, UnsafePointer(t1))
  }

  deinit {
    bytes.deinitialize(count: 96)
    bytes.deallocate()
    t1.deinitialize(count: t1CoefficientCount)
    t1.deallocate()
  }
}

// The backing bytes and coefficients are immutable after initialization. The
// cache is isolated by Mutex and every pointer borrow remains scoped.
extension MLDSAExpandedPublicKey: @unchecked Sendable {}
