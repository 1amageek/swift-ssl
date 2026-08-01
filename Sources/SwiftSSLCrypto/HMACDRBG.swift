import SwiftSSLCore

/// HMAC-DRBG with SHA-256 state as specified by SP 800-90A.
public struct HMACDRBG: ~Copyable, Sendable {
  public static let keyByteCount = 32
  public static let valueByteCount = 32
  public static let entropyByteCount = 32
  public static let maximumSeedMaterialByteCount = 4_096
  public static let maximumRequestByteCount = 1 << 20
  public static let reseedInterval: UInt64 = 1 << 48

  private var state: SecretBytes
  private var reseedCounter: UInt64

  public init(
    entropy: borrowing any EntropySource,
    nonce: Span<UInt8>,
    personalization: Span<UInt8>
  ) throws(DRBGError) {
    reseedCounter = 1
    state = Self.makeInitialState()
    let remainingAfterEntropy = Self.maximumSeedMaterialByteCount - Self.entropyByteCount
    guard nonce.count <= remainingAfterEntropy else {
      throw .inputTooLarge(limit: Self.maximumSeedMaterialByteCount, actual: Int.max)
    }
    let remainingAfterNonce = remainingAfterEntropy - nonce.count
    guard personalization.count <= remainingAfterNonce else {
      throw .inputTooLarge(limit: Self.maximumSeedMaterialByteCount, actual: Int.max)
    }
    let seedLength = Self.entropyByteCount + nonce.count + personalization.count

    var entropyBytes = ContiguousArray<UInt8>(repeating: 0, count: Self.entropyByteCount)
    defer { Self.wipe(&entropyBytes) }
    do {
      var output = entropyBytes.mutableSpan
      try entropy.fill(&output)
    } catch {
      throw .entropy(error)
    }

    var seed = ContiguousArray<UInt8>()
    seed.reserveCapacity(seedLength)
    seed.append(contentsOf: entropyBytes)
    Self.append(seed: &seed, bytes: nonce)
    Self.append(seed: &seed, bytes: personalization)

    defer { Self.wipe(&seed) }
    try update(seedMaterial: seed.span)
  }

  public mutating func reseed(
    using entropy: borrowing any EntropySource,
    additionalInput: Span<UInt8>
  ) throws(DRBGError) {
    let remainingAfterEntropy = Self.maximumSeedMaterialByteCount - Self.entropyByteCount
    guard additionalInput.count <= remainingAfterEntropy else {
      throw .inputTooLarge(limit: Self.maximumSeedMaterialByteCount, actual: Int.max)
    }
    let seedLength = Self.entropyByteCount + additionalInput.count
    var entropyBytes = ContiguousArray<UInt8>(repeating: 0, count: Self.entropyByteCount)
    defer { Self.wipe(&entropyBytes) }
    do {
      var output = entropyBytes.mutableSpan
      try entropy.fill(&output)
    } catch {
      throw .entropy(error)
    }
    var seed = ContiguousArray<UInt8>()
    seed.reserveCapacity(seedLength)
    seed.append(contentsOf: entropyBytes)
    Self.append(seed: &seed, bytes: additionalInput)
    defer { Self.wipe(&seed) }
    try update(seedMaterial: seed.span)
    reseedCounter = 1
  }

  public mutating func generate(
    into output: inout MutableSpan<UInt8>
  ) throws(DRBGError) {
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)
    try generate(additionalInput: Span(_unsafeElements: empty), into: &output)
  }

  public mutating func generate(
    additionalInput: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(DRBGError) {
    guard output.count <= Self.maximumRequestByteCount else {
      throw .outputTooLarge(limit: Self.maximumRequestByteCount, actual: output.count)
    }
    guard additionalInput.count <= Self.maximumSeedMaterialByteCount else {
      throw .inputTooLarge(limit: Self.maximumSeedMaterialByteCount, actual: additionalInput.count)
    }
    guard reseedCounter <= Self.reseedInterval else {
      throw .reseedRequired
    }

    if !additionalInput.isEmpty {
      try update(seedMaterial: additionalInput)
    }

    var key = copyKey()
    var value = copyValue()
    var nextValue = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)
    defer {
      Self.wipe(&key)
      Self.wipe(&value)
      Self.wipe(&nextValue)
    }

    var offset = 0
    while offset < output.count {
      try Self.hmac(key: key, message: value, into: &nextValue)
      Self.wipe(&value)
      value = nextValue
      nextValue = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)
      let count = Swift.min(Self.valueByteCount, output.count - offset)
      var index = 0
      while index < count {
        output[offset + index] = value[index]
        index += 1
      }
      offset += count
    }
    setState(key: key, value: value)
    try update(seedMaterial: additionalInput)
    reseedCounter += 1
  }

  private mutating func update(seedMaterial: Span<UInt8>) throws(DRBGError) {
    var key = copyKey()
    var value = copyValue()
    var message = ContiguousArray<UInt8>()
    var nextKey = ContiguousArray<UInt8>(repeating: 0, count: Self.keyByteCount)
    var nextValue = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)
    defer {
      Self.wipe(&key)
      Self.wipe(&value)
      Self.wipe(&message)
      Self.wipe(&nextKey)
      Self.wipe(&nextValue)
    }

    message.reserveCapacity(value.count + 1 + seedMaterial.count)
    message.append(contentsOf: value)
    message.append(0)
    Self.append(seed: &message, bytes: seedMaterial)
    try Self.hmac(key: key, message: message, into: &nextKey)
    Self.wipe(&key)
    key = nextKey
    nextKey = ContiguousArray<UInt8>(repeating: 0, count: Self.keyByteCount)
    try Self.hmac(key: key, message: value, into: &nextValue)
    Self.wipe(&value)
    value = nextValue
    nextValue = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)

    if !seedMaterial.isEmpty {
      Self.wipe(&message)
      message.removeAll(keepingCapacity: true)
      message.append(contentsOf: value)
      message.append(1)
      Self.append(seed: &message, bytes: seedMaterial)
      try Self.hmac(key: key, message: message, into: &nextKey)
      Self.wipe(&key)
      key = nextKey
      nextKey = ContiguousArray<UInt8>(repeating: 0, count: Self.keyByteCount)
      try Self.hmac(key: key, message: value, into: &nextValue)
      Self.wipe(&value)
      value = nextValue
      nextValue = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)
    }
    setState(key: key, value: value)
  }

  private func copyKey() -> ContiguousArray<UInt8> {
    state.withBorrowedBytes { bytes in
      var result = ContiguousArray<UInt8>(repeating: 0, count: Self.keyByteCount)
      var index = 0
      while index < Self.keyByteCount {
        result[index] = bytes[index]
        index += 1
      }
      return result
    }
  }

  private func copyValue() -> ContiguousArray<UInt8> {
    state.withBorrowedBytes { bytes in
      var result = ContiguousArray<UInt8>(repeating: 0, count: Self.valueByteCount)
      var index = 0
      while index < Self.valueByteCount {
        result[index] = bytes[Self.keyByteCount + index]
        index += 1
      }
      return result
    }
  }

  private mutating func setState(
    key: ContiguousArray<UInt8>,
    value: ContiguousArray<UInt8>
  ) {
    state.withMutableBorrowedBytes { destination in
      var index = 0
      while index < Self.keyByteCount {
        destination[index] = key[index]
        destination[Self.keyByteCount + index] = value[index]
        index += 1
      }
    }
  }

  private static func hmac(
    key: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>,
    into output: inout ContiguousArray<UInt8>
  ) throws(DRBGError) {
    do {
      var outputSpan = output.mutableSpan
      try HMACSHA256.authenticate(
        message.span,
        using: key.span,
        into: &outputSpan
      )
    } catch {
      throw .cryptographicFailure(error)
    }
  }

  private static func append(seed: inout ContiguousArray<UInt8>, bytes: Span<UInt8>) {
    var index = 0
    while index < bytes.count {
      seed.append(bytes[index])
      index += 1
    }
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }

  private static func makeInitialState() -> SecretBytes {
    // The state size is a compile-time constant within SecretByteCount's
    // supported range. Reaching the failure branch is an internal invariant
    // violation, not caller input, so it must not become a fallback state.
    do {
      let byteCount = try SecretByteCount(Self.keyByteCount + Self.valueByteCount)
      return SecretBytes(byteCount: byteCount) { destination in
        var index = 0
        while index < Self.keyByteCount {
          destination[index] = 0
          destination[Self.keyByteCount + index] = 1
          index += 1
        }
      }
    } catch {
      preconditionFailure("HMAC-DRBG state size exceeds SecretBytes limits")
    }
  }
}
