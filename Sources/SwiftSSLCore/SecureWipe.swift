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
  // WASM size-oriented optimization keeps the auditable eight-byte store schedule
  // from being recursively unrolled into target-specific multi-loop control flow.
  #if arch(wasm32)
  @_optimize(size)
  #endif
  @inline(never)
  package static func erase(
    _ pointer: UnsafeMutableRawPointer,
    byteCount: Int
  ) {
    precondition(byteCount >= 0, "Secure wipe byte count must not be negative")
    guard byteCount != 0 else { return }

    let groupedByteCount = byteCount & ~7
    let remainingByteCount = byteCount & 7
    var offset = 0
    if byteCount >= 8 {
      repeat {
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 1))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 2))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 3))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 4))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 5))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 6))
        ).store(0)
        VolatileMappedRegister<UInt8>(
          unsafeBitPattern: UInt(bitPattern: pointer.advanced(by: offset &+ 7))
        ).store(0)
        offset &+= 8
      } while offset != groupedByteCount
    }

    if remainingByteCount != 0 {
      var remainingOffset = 0
      repeat {
        let address = UInt(bitPattern: pointer.advanced(by: offset))
        VolatileMappedRegister<UInt8>(unsafeBitPattern: address).store(0)
        offset &+= 1
        remainingOffset &+= 1
      } while remainingOffset != remainingByteCount
    }
  }

  // Unsafe boundary invariants:
  // - The caller owns wordCount initialized UInt16 values at their natural alignment.
  // - VolatileMappedRegister addresses storage by integer address and does not create
  //   a typed pointer, bind memory, or retain an alias after each store.
  // - Every store covers one complete UInt16 value; no prefix or suffix is omitted.
  // - The caller retains exclusive access until all volatile stores complete.
  @inline(never)
  package static func eraseUInt16Words(
    _ pointer: UnsafeMutablePointer<UInt16>,
    wordCount: Int
  ) {
    precondition(wordCount >= 0, "Secure wipe word count must not be negative")

    for offset in 0..<wordCount {
      let address = UInt(bitPattern: pointer.advanced(by: offset))
      VolatileMappedRegister<UInt16>(unsafeBitPattern: address).store(0)
    }
  }

  // Unsafe boundary invariants:
  // - The caller owns wordCount initialized UInt32 values at their natural alignment.
  // - VolatileMappedRegister addresses storage by integer address and does not bind,
  //   rebind, retain, or return a typed pointer.
  // - Every store covers one complete UInt32 value; no prefix or suffix is omitted.
  // - The caller retains exclusive access until all volatile stores complete.
  @inline(never)
  package static func eraseUInt32Words(
    _ pointer: UnsafeMutablePointer<UInt32>,
    wordCount: Int
  ) {
    precondition(wordCount >= 0, "Secure wipe word count must not be negative")

    for offset in 0..<wordCount {
      let address = UInt(bitPattern: pointer.advanced(by: offset))
      VolatileMappedRegister<UInt32>(unsafeBitPattern: address).store(0)
    }
  }

  // Unsafe boundary invariants:
  // - The caller owns wordCount initialized 8-byte words at UInt64 alignment.
  // - VolatileMappedRegister addresses storage by integer address and does not bind,
  //   rebind, retain, or return a typed pointer.
  // - Every store covers one complete word; no prefix or suffix is omitted.
  // - The caller retains exclusive access until all volatile stores complete.
  @inline(never)
  package static func eraseUInt64Words(
    _ pointer: UnsafeMutableRawPointer,
    wordCount: Int
  ) {
    precondition(wordCount >= 0, "Secure wipe word count must not be negative")
    precondition(
      UInt(bitPattern: pointer) % UInt(MemoryLayout<UInt64>.alignment) == 0,
      "Secure wipe address must be UInt64 aligned"
    )

    for offset in 0..<wordCount {
      let address = UInt(
        bitPattern: pointer.advanced(by: offset * MemoryLayout<UInt64>.stride)
      )
      VolatileMappedRegister<UInt64>(unsafeBitPattern: address).store(0)
    }
  }
}
