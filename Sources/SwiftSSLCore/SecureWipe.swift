import _Volatile

package enum SecureWipe {
  // Unsafe boundary invariants:
  // - The caller owns an initialized byte range of exactly byteCount bytes.
  // - The owner remains alive and exclusively mutable for the entire call.
  // - byteCount is nonnegative, so every derived offset remains in the range.
  // - UInt8 has stride and alignment one; no typed rebind or wider access occurs.
  // - No derived pointer or address escapes this function.
  // - The caller performs deinitialization and exactly-once deallocation only after return.
  // - No Sendable boundary is crossed while the volatile stores are in progress.
  @inline(never)
  package static func erase(
    _ pointer: UnsafeMutableRawPointer,
    byteCount: Int
  ) {
    precondition(byteCount >= 0, "Secure wipe byte count must not be negative")

    for offset in 0..<byteCount {
      let address = UInt(bitPattern: pointer.advanced(by: offset))
      VolatileMappedRegister<UInt8>(unsafeBitPattern: address).store(0)
    }
  }
}
