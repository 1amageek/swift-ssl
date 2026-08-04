import SSLCore

extension P384ECDSA {
  /// Creates an RFC 6979 deterministic P-384 ECDSA signature in `r || s` form.
  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing P384PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    try WeierstrassECDSASigning.sign(
      messageHash: messageHash,
      privateKey: privateKey,
      curve: .p384
    )
  }
}

extension P521ECDSA {
  /// Creates an RFC 6979 deterministic P-521 ECDSA signature in `r || s` form.
  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing P521PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    try WeierstrassECDSASigning.sign(
      messageHash: messageHash,
      privateKey: privateKey,
      curve: .p521
    )
  }
}

private enum WeierstrassECDSASigning {
  static func sign(
    messageHash: Span<UInt8>,
    privateKey: borrowing P384PrivateKey,
    curve: WeierstrassECDSA.Curve
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    try privateKey.withBorrowedBytes { bytes throws(CryptoInputError) in
      try signWithBytes(messageHash: messageHash, privateBytes: bytes, curve: curve)
    }
  }

  static func sign(
    messageHash: Span<UInt8>,
    privateKey: borrowing P521PrivateKey,
    curve: WeierstrassECDSA.Curve
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    try privateKey.withBorrowedBytes { bytes throws(CryptoInputError) in
      try signWithBytes(messageHash: messageHash, privateBytes: bytes, curve: curve)
    }
  }

  private static func signWithBytes(
    messageHash: Span<UInt8>,
    privateBytes: Span<UInt8>,
    curve: WeierstrassECDSA.Curve
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    var privateScalar = WeierstrassECDSA.FixedUInt(
      bytes: privateBytes, byteCount: curve.byteCount
    )
    defer { privateScalar.wipe() }
    let digest = WeierstrassECDSA.FixedUInt(
      truncatingDigest: messageHash, curve: curve
    )
    var state = try RFC6979State(
      privateBytes: privateBytes,
      messageHash: digest,
      curve: curve
    )

    var attempts = 0
    while attempts < 256 {
      var nonce = try state.nextCandidate()
      defer { nonce.wipe() }
      guard !nonce.isZero, nonce < curve.order else {
        try state.rejectCandidate()
        attempts += 1
        continue
      }

      let point = WeierstrassECDSA.Point.scalarMultiplySecret(
        .generator(curve), scalar: nonce, curve: curve
      )
      guard let affine = point.affine(curve: curve) else {
        try state.rejectCandidate()
        attempts += 1
        continue
      }
      let r = affine.x.modulo(curve.order)
      guard !r.isZero else {
        try state.rejectCandidate()
        attempts += 1
        continue
      }
      let inverse = nonce.power(
        curve.order.subtractingSmall(2),
        modulus: curve.order,
        bitCount: curve.bitCount
      )
      let product = r.moduloMultiply(privateScalar, modulus: curve.order)
      let sum = digest.moduloAdd(product, modulus: curve.order)
      let s = inverse.moduloMultiply(sum, modulus: curve.order)
      guard !s.isZero else {
        try state.rejectCandidate()
        attempts += 1
        continue
      }
      var signature = ContiguousArray<UInt8>()
      signature.reserveCapacity(curve.signatureByteCount)
      signature.append(contentsOf: r.encoded(byteCount: curve.byteCount))
      signature.append(contentsOf: s.encoded(byteCount: curve.byteCount))
      return signature
    }
    throw .invalidSignature
  }

  private struct RFC6979State: ~Copyable {
    private var key: SecretBytes
    private var value: SecretBytes
    private let curve: WeierstrassECDSA.Curve

    init(
      privateBytes: Span<UInt8>,
      messageHash: WeierstrassECDSA.FixedUInt,
      curve: WeierstrassECDSA.Curve
    ) throws(CryptoInputError) {
      self.curve = curve
      let keyCount = try Self.secretByteCount(curve.hashByteCount)
      var key = Self.filled(byteCount: keyCount, value: 0)
      var value = Self.filled(byteCount: keyCount, value: 1)
      var first = try Self.message(value: value, marker: 0, privateBytes: privateBytes, hash: messageHash, curve: curve)
      key = try Self.hmac(key: key, message: first, curve: curve)
      Self.wipe(&first)
      var nextValue = try Self.hmac(key: key, message: value, curve: curve)
      value = nextValue
      var second = try Self.message(value: value, marker: 1, privateBytes: privateBytes, hash: messageHash, curve: curve)
      key = try Self.hmac(key: key, message: second, curve: curve)
      Self.wipe(&second)
      nextValue = try Self.hmac(key: key, message: value, curve: curve)
      value = nextValue
      self.key = key
      self.value = value
    }

    mutating func nextCandidate() throws(CryptoInputError) -> WeierstrassECDSA.FixedUInt {
      var candidate = ContiguousArray<UInt8>()
      candidate.reserveCapacity(curve.byteCount)
      while candidate.count < curve.byteCount {
        let next = try Self.hmac(key: key, message: value, curve: curve)
        value = next
        value.withBorrowedBytes { bytes in
          var index = 0
          let needed = min(bytes.count, curve.byteCount - candidate.count)
          while index < needed { candidate.append(bytes[index]); index += 1 }
        }
      }
      if curve.unusedTopBits != 0 { candidate[0] &= 0x01 }
      defer { Self.wipe(&candidate) }
      return WeierstrassECDSA.FixedUInt(bytes: candidate.span, byteCount: curve.byteCount)
    }

    mutating func rejectCandidate() throws(CryptoInputError) {
      var message = ContiguousArray<UInt8>()
      message.reserveCapacity(value.count + 1)
      value.withBorrowedBytes { bytes in
        var index = 0
        while index < bytes.count { message.append(bytes[index]); index += 1 }
      }
      message.append(0)
      let nextKey = try Self.hmac(key: key, message: message, curve: curve)
      Self.wipe(&message)
      key = nextKey
      value = try Self.hmac(key: key, message: value, curve: curve)
    }

    private static func secretByteCount(_ count: Int) throws(CryptoInputError) -> SecretByteCount {
      do { return try SecretByteCount(count) }
      catch { throw .invalidLength(expected: 1, actual: count) }
    }

    private static func filled(byteCount: SecretByteCount, value: UInt8) -> SecretBytes {
      SecretBytes(byteCount: byteCount) { destination in
        var index = 0
        while index < destination.count { destination[index] = value; index += 1 }
      }
    }

    private static func message(
      value: borrowing SecretBytes,
      marker: UInt8,
      privateBytes: Span<UInt8>,
      hash: WeierstrassECDSA.FixedUInt,
      curve: WeierstrassECDSA.Curve
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
      var result = ContiguousArray<UInt8>()
      result.reserveCapacity(curve.hashByteCount + privateBytes.count + 1)
      value.withBorrowedBytes { bytes in
        var index = 0
        while index < bytes.count { result.append(bytes[index]); index += 1 }
      }
      result.append(marker)
      var privateIndex = 0
      while privateIndex < privateBytes.count {
        result.append(privateBytes[privateIndex])
        privateIndex += 1
      }
      // RFC 6979 bits2octets: bits2int(hash) is reduced modulo the group
      // order before it is fed into the deterministic HMAC state.
      result.append(contentsOf: hash.modulo(curve.order).encoded(byteCount: curve.byteCount))
      return result
    }

    private static func hmac(
      key: borrowing SecretBytes,
      message: borrowing SecretBytes,
      curve: WeierstrassECDSA.Curve
    ) throws(CryptoInputError) -> SecretBytes {
      var bytes = ContiguousArray<UInt8>()
      message.withBorrowedBytes { input in
        var index = 0
        while index < input.count { bytes.append(input[index]); index += 1 }
      }
      defer { Self.wipe(&bytes) }
      return try hmac(key: key, message: bytes, curve: curve)
    }

    private static func hmac(
      key: borrowing SecretBytes,
      message: ContiguousArray<UInt8>,
      curve: WeierstrassECDSA.Curve
    ) throws(CryptoInputError) -> SecretBytes {
      try key.withBorrowedBytes { keyBytes throws(CryptoInputError) in
        switch curve {
        case .p384:
          var context = try HMACSHA384.makeContext(authenticatingWith: keyBytes)
          try context.update(message.span)
          var output = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA384.tagByteCount)
          var destination = output.mutableSpan
          try context.finalize(into: &destination)
          defer { Self.wipe(&output) }
          do { return try SecretBytes(copying: output.span) }
          catch { throw .invalidRange }
        case .p521:
          var context = try HMACSHA512.makeContext(authenticatingWith: keyBytes)
          try context.update(message.span)
          var output = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA512.tagByteCount)
          var destination = output.mutableSpan
          try context.finalize(into: &destination)
          defer { Self.wipe(&output) }
          do { return try SecretBytes(copying: output.span) }
          catch { throw .invalidRange }
        }
      }
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
      bytes.withUnsafeMutableBufferPointer { buffer in
        guard let base = buffer.baseAddress else { return }
        SecureWipe.erase(UnsafeMutableRawPointer(base), byteCount: buffer.count)
      }
    }
  }
}

extension WeierstrassECDSA.Curve {
  var hashByteCount: Int { self == .p384 ? 48 : 64 }
}
