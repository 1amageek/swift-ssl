import SwiftSSLCore

/// Allocation-free RFC 9180 labeled HKDF operations for SHA-256.
enum HPKESHA256LabeledKDF {
  static let digestByteCount = SHA256.digestByteCount

  static func extract(
    salt: Span<UInt8>,
    suiteID: Span<UInt8>,
    label: StaticString,
    input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try HMACSHA256Core.withPreparedContexts(
      authenticatingWith: salt
    ) { preparedInner, preparedOuter throws(CryptoInputError) in
      try HMACSHA256Core.withWorkingContexts(
        innerContext: preparedInner,
        outerContext: preparedOuter
      ) { inner, outer throws(CryptoInputError) in
        try updateLabeledPrefix(
          &inner,
          encodedLength: nil,
          suiteID: suiteID,
          label: label
        )
        try inner.update(input)
        try HMACSHA256Core.finalizeAuthenticationCode(
          innerContext: &inner,
          outerContext: &outer,
          into: &output
        )
      }
    }
  }

  static func expand(
    pseudorandomKey: Span<UInt8>,
    suiteID: Span<UInt8>,
    label: StaticString,
    outputByteCount: Int,
    updateInfo: (inout SHA256Context) throws(CryptoInputError) -> Void,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    precondition(outputByteCount == output.count)
    precondition(outputByteCount > 0 && outputByteCount <= digestByteCount)

    try HMACSHA256Core.withPreparedContexts(
      authenticatingWith: pseudorandomKey
    ) { preparedInner, preparedOuter throws(CryptoInputError) in
      try HMACSHA256Core.withWorkingContexts(
        innerContext: preparedInner,
        outerContext: preparedOuter
      ) { inner, outer throws(CryptoInputError) in
        try updateLabeledPrefix(
          &inner,
          encodedLength: UInt16(outputByteCount),
          suiteID: suiteID,
          label: label
        )
        try updateInfo(&inner)
        var counter: UInt8 = 1
        try withUnsafeBytes(of: &counter) {
          bytes throws(CryptoInputError) in
          try inner.update(
            Span(_unsafeElements: bytes.bindMemory(to: UInt8.self))
          )
        }

        if outputByteCount == digestByteCount {
          try HMACSHA256Core.finalizeAuthenticationCode(
            innerContext: &inner,
            outerContext: &outer,
            into: &output
          )
          return
        }

        var fullOutput = SIMD32<UInt8>(repeating: 0)
        try withUnsafeMutableBytes(of: &fullOutput) {
          bytes throws(CryptoInputError) in
          let pointer = bytes.baseAddress.unsafelyUnwrapped
            .assumingMemoryBound(to: UInt8.self)
          defer {
            SecureWipe.erase(pointer, byteCount: bytes.count)
          }
          var fullOutputSpan = MutableSpan(
            _unsafeStart: pointer,
            count: digestByteCount
          )
          try HMACSHA256Core.finalizeAuthenticationCode(
            innerContext: &inner,
            outerContext: &outer,
            into: &fullOutputSpan
          )
          var index = 0
          while index < outputByteCount {
            output[index] = pointer[index]
            index += 1
          }
        }
      }
    }
  }

  private static func updateLabeledPrefix(
    _ context: inout SHA256Context,
    encodedLength: UInt16?,
    suiteID: Span<UInt8>,
    label: StaticString
  ) throws(CryptoInputError) {
    let encodedLengthByteCount = encodedLength == nil ? 0 : 2
    let prefixByteCount =
      encodedLengthByteCount
      + 7
      + suiteID.count
      + label.utf8CodeUnitCount
    precondition(prefixByteCount <= 32)
    var prefix = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - prefix owns exactly 32 initialized bytes and the computed prefix count
    //   is checked before any write.
    // - StaticString owns immutable UTF-8 storage for the process lifetime.
    // - suiteID remains borrowed for this synchronous copy and SHA-256 update.
    // - No derived pointer escapes, aliases mutable input, or crosses Sendable.
    try withUnsafeMutableBytes(of: &prefix) {
      bytes throws(CryptoInputError) in
      let destination = bytes.baseAddress.unsafelyUnwrapped
        .assumingMemoryBound(to: UInt8.self)
      var offset = 0
      if let encodedLength {
        destination[0] = UInt8(truncatingIfNeeded: encodedLength >> 8)
        destination[1] = UInt8(truncatingIfNeeded: encodedLength)
        offset = 2
      }
      copy("HPKE-v1", into: destination, at: &offset)
      var suiteIndex = 0
      while suiteIndex < suiteID.count {
        destination[offset] = suiteID[suiteIndex]
        suiteIndex += 1
        offset += 1
      }
      copy(label, into: destination, at: &offset)
      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(destination),
        count: prefixByteCount
      )
      try context.update(Span(_unsafeElements: buffer))
    }
  }

  @inline(__always)
  private static func copy(
    _ value: StaticString,
    into destination: UnsafeMutablePointer<UInt8>,
    at offset: inout Int
  ) {
    let source = value.utf8Start
    var index = 0
    while index < value.utf8CodeUnitCount {
      destination[offset] = source[index]
      index += 1
      offset += 1
    }
  }
}
