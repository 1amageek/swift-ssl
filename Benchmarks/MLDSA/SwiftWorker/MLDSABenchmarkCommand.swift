import SwiftSSL

#if canImport(Darwin)
  import Darwin
#endif

@main
enum MLDSABenchmarkCommand {
  private enum Operation: String {
    case keyGeneration = "keygen"
    case signing = "sign"
    case verification = "verify"
  }

  private enum ArgumentError: Error {
    case invalidArguments
    case validationFailure
  }

  private struct FixedEntropy: EntropySource {
    let byte: UInt8

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
    }
  }

  private struct Measurement {
    let nanoseconds: UInt64
    let checksum: UInt64
  }

  #if canImport(Darwin)
    private struct AllocationProbe {
      let start: @convention(c) () -> Void
      let stopAndPrint: @convention(c) () -> Void

      init() throws {
        let defaultSearchHandle = UnsafeMutableRawPointer(
          bitPattern: UInt(bitPattern: -2)
        )
        guard
          let startAddress = dlsym(
            defaultSearchHandle,
            "swift_ssl_allocation_probe_start"
          ),
          let stopAddress = dlsym(
            defaultSearchHandle,
            "swift_ssl_allocation_probe_stop_and_print"
          )
        else {
          throw ArgumentError.validationFailure
        }
        start = unsafeBitCast(
          startAddress,
          to: (@convention(c) () -> Void).self
        )
        stopAndPrint = unsafeBitCast(
          stopAddress,
          to: (@convention(c) () -> Void).self
        )
      }
    }
  #endif

  static func main() throws {
    let arguments = CommandLine.arguments
    if arguments.count > 1, arguments[1].hasPrefix("--") {
      try runValidation(arguments)
      return
    }
    guard
      arguments.count == 4,
      let operation = Operation(rawValue: arguments[1]),
      let iterations = Int(arguments[2]),
      let warmupIterations = Int(arguments[3]),
      iterations > 0,
      warmupIterations >= 0
    else {
      throw ArgumentError.invalidArguments
    }
    let measurement = try run(
      operation: operation,
      iterations: iterations,
      warmupIterations: warmupIterations
    )
    print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
  }

  private static func run(
    operation: Operation,
    iterations: Int,
    warmupIterations: Int
  ) throws -> Measurement {
    let seed = deterministicBytes(count: MLDSA65.seedByteCount, seed: 0x65)
    let pair = try MLDSA65.keyPair(seed: seed.span)
    let message = deterministicBytes(count: 1_024, seed: 0xA5)
    let context = deterministicBytes(count: 17, seed: 0xC3)
    var signature = try MLDSA65.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      entropy: FixedEntropy(byte: 0x73)
    )
    var warmupIteration = 0
    switch operation {
    case .keyGeneration:
      while warmupIteration < warmupIterations {
        _ = try keyGenerationChecksum(iteration: warmupIteration)
        warmupIteration += 1
      }
    case .signing:
      while warmupIteration < warmupIterations {
        var output = signature.mutableSpan
        try MLDSA65.sign(
          message: message.span,
          context: context.span,
          using: pair.privateKey,
          into: &output
        )
        warmupIteration += 1
      }
    case .verification:
      while warmupIteration < warmupIterations {
        guard
          try MLDSA65.verify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair.publicKey
          )
        else {
          throw ArgumentError.validationFailure
        }
        warmupIteration += 1
      }
    }
    var checksum: UInt64 = 0
    let start = monotonicNanoseconds()
    switch operation {
    case .keyGeneration:
      var iteration = 0
      while iteration < iterations {
        checksum &+= try keyGenerationChecksum(iteration: iteration)
        iteration += 1
      }
    case .signing:
      var iteration = 0
      while iteration < iterations {
        var output = signature.mutableSpan
        try MLDSA65.sign(
          message: message.span,
          context: context.span,
          using: pair.privateKey,
          into: &output
        )
        checksum &+= UInt64(signature[iteration % signature.count])
        iteration += 1
      }
    case .verification:
      var iteration = 0
      while iteration < iterations {
        guard
          try MLDSA65.verify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair.publicKey
          )
        else {
          throw ArgumentError.validationFailure
        }
        checksum &+= UInt64(signature[iteration % signature.count])
        iteration += 1
      }
    }
    return Measurement(
      nanoseconds: monotonicNanoseconds() &- start,
      checksum: checksum
    )
  }

  private static func keyGenerationChecksum(
    iteration: Int
  ) throws -> UInt64 {
    let generated = try MLDSA65.keyPair()
    return UInt64(
      generated.publicKey.withBorrowedBytes {
        $0[iteration % MLDSA65.publicKeyByteCount]
      }
    )
  }

  private static func runValidation(_ arguments: [String]) throws {
    switch arguments[1] {
    case "--memory":
      guard
        arguments.count == 4,
        let operation = Operation(rawValue: arguments[2]),
        let iterations = Int(arguments[3]),
        iterations > 0
      else {
        throw ArgumentError.invalidArguments
      }
      try runMemoryMeasurement(operation: operation, iterations: iterations)
    case "--fixture":
      guard arguments.count == 6 else { throw ArgumentError.invalidArguments }
      let seed = try decodeHex(arguments[2], expectedByteCount: MLDSA65.seedByteCount)
      let message = try decodeHex(arguments[3], expectedByteCount: 64)
      let context = try decodeHex(arguments[4], expectedByteCount: 19)
      let randomizer = try decodeHex(
        arguments[5],
        expectedByteCount: MLDSA65.randomizerByteCount
      )
      let pair = try MLDSA65.keyPair(seed: seed.span)
      let signature = try MLDSA65.sign(
        message: message.span,
        context: context.span,
        using: pair.privateKey,
        entropy: ByteEntropy(bytes: randomizer)
      )
      print("FIXTURE,\(encodeHex(pair.publicKey.span)),\(encodeHex(signature.span))")
    case "--validate":
      guard arguments.count == 7 else { throw ArgumentError.invalidArguments }
      let seed = try decodeHex(arguments[2], expectedByteCount: MLDSA65.seedByteCount)
      let expectedPublic = try decodeHex(
        arguments[3],
        expectedByteCount: MLDSA65.publicKeyByteCount
      )
      let signature = try decodeHex(
        arguments[4],
        expectedByteCount: MLDSA65.signatureByteCount
      )
      let message = try decodeHex(arguments[5], expectedByteCount: 64)
      let context = try decodeHex(arguments[6], expectedByteCount: 19)
      let pair = try MLDSA65.keyPair(seed: seed.span)
      guard
        equal(pair.publicKey.span, expectedPublic.span),
        try MLDSA65.verify(
          signature: signature.span,
          message: message.span,
          context: context.span,
          using: pair.publicKey
        )
      else {
        throw ArgumentError.validationFailure
      }
      print("VALIDATED")
    case "--verify":
      guard arguments.count == 6 else { throw ArgumentError.invalidArguments }
      let encodedPublic = try decodeHex(
        arguments[2],
        expectedByteCount: MLDSA65.publicKeyByteCount
      )
      let signature = try decodeHex(
        arguments[3],
        expectedByteCount: MLDSA65.signatureByteCount
      )
      let message = try decodeHex(arguments[4], expectedByteCount: 64)
      let context = try decodeHex(arguments[5], expectedByteCount: 19)
      let publicKey = try MLDSA65PublicKey(bytes: encodedPublic.span)
      let valid = try MLDSA65.verify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: publicKey
      )
      print("VERIFIED,\(valid ? 1 : 0)")
    default:
      throw ArgumentError.invalidArguments
    }
  }

  private static func runMemoryMeasurement(
    operation: Operation,
    iterations: Int
  ) throws {
    #if canImport(Darwin)
      let probe = try AllocationProbe()
      let checksum: UInt64
      switch operation {
      case .keyGeneration:
        // Initialize process-global allocator/runtime state outside the probe.
        // Key generation itself remains fully included in every measured loop.
        _ = try memoryKeyGeneration(iterations: 1)
        probe.start()
        do {
          checksum = try memoryKeyGeneration(iterations: iterations)
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .signing:
        let seed = deterministicBytes(count: MLDSA65.seedByteCount, seed: 0x65)
        let pair = try MLDSA65.keyPair(seed: seed.span)
        let message = deterministicBytes(count: 1_024, seed: 0xA5)
        let context = deterministicBytes(count: 17, seed: 0xC3)
        var signature = try MLDSA65.sign(
          message: message.span,
          context: context.span,
          using: pair.privateKey,
          entropy: FixedEntropy(byte: 0x73)
        )
        probe.start()
        do {
          checksum = try memorySigning(
            pair: pair,
            message: message,
            context: context,
            signature: &signature,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .verification:
        let seed = deterministicBytes(count: MLDSA65.seedByteCount, seed: 0x65)
        let pair = try MLDSA65.keyPair(seed: seed.span)
        let message = deterministicBytes(count: 1_024, seed: 0xA5)
        let context = deterministicBytes(count: 17, seed: 0xC3)
        let signature = try MLDSA65.sign(
          message: message.span,
          context: context.span,
          using: pair.privateKey,
          entropy: FixedEntropy(byte: 0x73)
        )
        guard
          try MLDSA65.verify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair.publicKey
          )
        else {
          throw ArgumentError.validationFailure
        }
        probe.start()
        do {
          checksum = try memoryVerification(
            pair: pair,
            message: message,
            context: context,
            signature: signature,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      }
      probe.stopAndPrint()
      print("MEMORY_CHECKSUM,\(iterations),\(checksum)")
    #else
      throw ArgumentError.validationFailure
    #endif
  }

  private static func memoryKeyGeneration(iterations: Int) throws -> UInt64 {
    let entropy = FixedEntropy(byte: 0x51)
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let pair = try MLDSA65.keyPair(using: entropy)
      checksum &+= UInt64(
        pair.publicKey.withBorrowedBytes {
          $0[iteration % MLDSA65.publicKeyByteCount]
        }
      )
      iteration += 1
    }
    return checksum
  }

  private static func memorySigning(
    pair: borrowing MLDSA65KeyPair,
    message: borrowing ContiguousArray<UInt8>,
    context: borrowing ContiguousArray<UInt8>,
    signature: inout ContiguousArray<UInt8>,
    iterations: Int
  ) throws -> UInt64 {
    let entropy = FixedEntropy(byte: 0x73)
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var output = signature.mutableSpan
      try MLDSA65.sign(
        message: message.span,
        context: context.span,
        using: pair.privateKey,
        entropy: entropy,
        into: &output
      )
      checksum &+= UInt64(signature[iteration % signature.count])
      iteration += 1
    }
    return checksum
  }

  private static func memoryVerification(
    pair: borrowing MLDSA65KeyPair,
    message: borrowing ContiguousArray<UInt8>,
    context: borrowing ContiguousArray<UInt8>,
    signature: borrowing ContiguousArray<UInt8>,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      guard
        try MLDSA65.verify(
          signature: signature.span,
          message: message.span,
          context: context.span,
          using: pair.publicKey
        )
      else {
        throw ArgumentError.validationFailure
      }
      checksum &+= UInt64(signature[iteration % signature.count])
      iteration += 1
    }
    return checksum
  }

  private struct ByteEntropy: EntropySource {
    let bytes: ContiguousArray<UInt8>

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      guard destination.count == bytes.count else {
        throw .partialFill(expected: destination.count, actual: bytes.count)
      }
      var index = 0
      while index < bytes.count {
        destination[index] = bytes[index]
        index += 1
      }
    }
  }

  private static func deterministicBytes(
    count: Int,
    seed: UInt64
  ) -> ContiguousArray<UInt8> {
    var state = seed
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(count)
    var index = 0
    while index < count {
      state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
      result.append(UInt8(truncatingIfNeeded: state >> 32))
      index += 1
    }
    return result
  }

  private static func decodeHex(
    _ value: String,
    expectedByteCount: Int
  ) throws -> ContiguousArray<UInt8> {
    guard value.count == expectedByteCount * 2 else {
      throw ArgumentError.invalidArguments
    }
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(expectedByteCount)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        throw ArgumentError.invalidArguments
      }
      bytes.append(byte)
      index = next
    }
    return bytes
  }

  private static func encodeHex(_ input: Span<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var result = String()
    result.reserveCapacity(input.count * 2)
    var index = 0
    while index < input.count {
      result.unicodeScalars.append(UnicodeScalar(digits[Int(input[index] >> 4)]))
      result.unicodeScalars.append(UnicodeScalar(digits[Int(input[index] & 0x0F)]))
      index += 1
    }
    return result
  }

  private static func equal(_ lhs: Span<UInt8>, _ rhs: Span<UInt8>) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    var index = 0
    while index < lhs.count {
      difference |= lhs[index] ^ rhs[index]
      index += 1
    }
    return difference == 0
  }

  private static func monotonicNanoseconds() -> UInt64 {
    #if canImport(Darwin)
      var timebase = mach_timebase_info_data_t()
      mach_timebase_info(&timebase)
      return mach_absolute_time()
        &* UInt64(timebase.numer)
        / UInt64(timebase.denom)
    #else
      return 0
    #endif
  }
}
