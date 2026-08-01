#if os(macOS) && arch(arm64) && canImport(simd)
  import simd

  @inline(never)
  public func swiftSHA256FourRounds(
    _ state0Pointer: UnsafeMutablePointer<SIMD4<UInt32>>,
    _ state1Pointer: UnsafeMutablePointer<SIMD4<UInt32>>,
    _ workPointer: UnsafePointer<SIMD4<UInt32>>
  ) {
    var state0 = state0Pointer.pointee
    var state1 = state1Pointer.pointee
    let work = workPointer.pointee
    let previousState0 = state0
    state0 = vsha256hq_u32(state0, state1, work)
    state1 = vsha256h2q_u32(state1, previousState0, work)
    state0Pointer.pointee = state0
    state1Pointer.pointee = state1
  }
#endif
