import SSL

#if canImport(Darwin)
  import Darwin
#endif

private protocol MLDSABenchmarkParameterSet:
  InPlaceContextualRandomizedDigitalSignature
{
  associatedtype BenchmarkKeyPair: ~Copyable

  static var seedByteCount: Int { get }
  static var publicKeyByteCount: Int { get }
  static var signatureByteCount: Int { get }
  static var randomizerByteCount: Int { get }

  static func benchmarkKeyPair(
    seed: Span<UInt8>
  ) throws(MLDSAError) -> BenchmarkKeyPair

  static func benchmarkKeyPair() throws(MLDSAError) -> BenchmarkKeyPair

  static func benchmarkKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> BenchmarkKeyPair

  static func benchmarkPublicByte(
    at index: Int,
    from pair: borrowing BenchmarkKeyPair
  ) -> UInt64

  static func benchmarkPublicKeyBytes(
    from pair: borrowing BenchmarkKeyPair
  ) -> ContiguousArray<UInt8>

  static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing BenchmarkKeyPair,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8>

  static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing BenchmarkKeyPair,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError)

  static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing BenchmarkKeyPair,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError)

  static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing BenchmarkKeyPair
  ) throws(MLDSAError) -> Bool

  static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKeyBytes: Span<UInt8>
  ) throws(MLDSAError) -> Bool
}

private func copyBenchmarkBytes(_ input: Span<UInt8>) -> ContiguousArray<UInt8> {
  var result = ContiguousArray<UInt8>()
  result.reserveCapacity(input.count)
  var index = 0
  while index < input.count {
    result.append(input[index])
    index += 1
  }
  return result
}

extension MLDSA44: MLDSABenchmarkParameterSet {
  fileprivate typealias BenchmarkKeyPair = MLDSA44KeyPair

  fileprivate static func benchmarkKeyPair(
    seed: Span<UInt8>
  ) throws(MLDSAError) -> MLDSA44KeyPair {
    try keyPair(seed: seed)
  }

  fileprivate static func benchmarkKeyPair() throws(MLDSAError) -> MLDSA44KeyPair {
    try keyPair()
  }

  fileprivate static func benchmarkKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA44KeyPair {
    try keyPair(using: entropy)
  }

  fileprivate static func benchmarkPublicByte(
    at index: Int,
    from pair: borrowing MLDSA44KeyPair
  ) -> UInt64 {
    UInt64(pair.publicKey.span[index])
  }

  fileprivate static func benchmarkPublicKeyBytes(
    from pair: borrowing MLDSA44KeyPair
  ) -> ContiguousArray<UInt8> {
    copyBenchmarkBytes(pair.publicKey.span)
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA44KeyPair,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA44KeyPair,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy,
      into: &signature
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA44KeyPair,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      into: &signature
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA44KeyPair
  ) throws(MLDSAError) -> Bool {
    try verify(
      signature: signature,
      message: message,
      context: context,
      using: pair.publicKey
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKeyBytes: Span<UInt8>
  ) throws(MLDSAError) -> Bool {
    let publicKey = try MLDSA44PublicKey(bytes: publicKeyBytes)
    return try verify(
      signature: signature,
      message: message,
      context: context,
      using: publicKey
    )
  }
}

extension MLDSA65: MLDSABenchmarkParameterSet {
  fileprivate typealias BenchmarkKeyPair = MLDSA65KeyPair

  fileprivate static func benchmarkKeyPair(
    seed: Span<UInt8>
  ) throws(MLDSAError) -> MLDSA65KeyPair {
    try keyPair(seed: seed)
  }

  fileprivate static func benchmarkKeyPair() throws(MLDSAError) -> MLDSA65KeyPair {
    try keyPair()
  }

  fileprivate static func benchmarkKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA65KeyPair {
    try keyPair(using: entropy)
  }

  fileprivate static func benchmarkPublicByte(
    at index: Int,
    from pair: borrowing MLDSA65KeyPair
  ) -> UInt64 {
    UInt64(pair.publicKey.span[index])
  }

  fileprivate static func benchmarkPublicKeyBytes(
    from pair: borrowing MLDSA65KeyPair
  ) -> ContiguousArray<UInt8> {
    copyBenchmarkBytes(pair.publicKey.span)
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA65KeyPair,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA65KeyPair,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy,
      into: &signature
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA65KeyPair,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      into: &signature
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA65KeyPair
  ) throws(MLDSAError) -> Bool {
    try verify(
      signature: signature,
      message: message,
      context: context,
      using: pair.publicKey
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKeyBytes: Span<UInt8>
  ) throws(MLDSAError) -> Bool {
    let publicKey = try MLDSA65PublicKey(bytes: publicKeyBytes)
    return try verify(
      signature: signature,
      message: message,
      context: context,
      using: publicKey
    )
  }
}

extension MLDSA87: MLDSABenchmarkParameterSet {
  fileprivate typealias BenchmarkKeyPair = MLDSA87KeyPair

  fileprivate static func benchmarkKeyPair(
    seed: Span<UInt8>
  ) throws(MLDSAError) -> MLDSA87KeyPair {
    try keyPair(seed: seed)
  }

  fileprivate static func benchmarkKeyPair() throws(MLDSAError) -> MLDSA87KeyPair {
    try keyPair()
  }

  fileprivate static func benchmarkKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA87KeyPair {
    try keyPair(using: entropy)
  }

  fileprivate static func benchmarkPublicByte(
    at index: Int,
    from pair: borrowing MLDSA87KeyPair
  ) -> UInt64 {
    UInt64(pair.publicKey.span[index])
  }

  fileprivate static func benchmarkPublicKeyBytes(
    from pair: borrowing MLDSA87KeyPair
  ) -> ContiguousArray<UInt8> {
    copyBenchmarkBytes(pair.publicKey.span)
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA87KeyPair,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA87KeyPair,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      entropy: entropy,
      into: &signature
    )
  }

  fileprivate static func benchmarkSign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA87KeyPair,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: pair.privateKey,
      into: &signature
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using pair: borrowing MLDSA87KeyPair
  ) throws(MLDSAError) -> Bool {
    try verify(
      signature: signature,
      message: message,
      context: context,
      using: pair.publicKey
    )
  }

  fileprivate static func benchmarkVerify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKeyBytes: Span<UInt8>
  ) throws(MLDSAError) -> Bool {
    let publicKey = try MLDSA87PublicKey(bytes: publicKeyBytes)
    return try verify(
      signature: signature,
      message: message,
      context: context,
      using: publicKey
    )
  }
}

@main
enum MLDSABenchmarkCommand {
  private enum ParameterSet: String {
    case mlDSA44 = "44"
    case mlDSA65 = "65"
    case mlDSA87 = "87"
  }

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
      arguments.count == 5,
      let parameterSet = ParameterSet(rawValue: arguments[1]),
      let operation = Operation(rawValue: arguments[2]),
      let iterations = Int(arguments[3]),
      let warmupIterations = Int(arguments[4]),
      iterations > 0,
      warmupIterations >= 0
    else {
      throw ArgumentError.invalidArguments
    }
    let measurement: Measurement
    switch parameterSet {
    case .mlDSA44:
      measurement = try run(
        MLDSA44.self,
        operation: operation,
        iterations: iterations,
        warmupIterations: warmupIterations
      )
    case .mlDSA65:
      measurement = try run(
        MLDSA65.self,
        operation: operation,
        iterations: iterations,
        warmupIterations: warmupIterations
      )
    case .mlDSA87:
      measurement = try run(
        MLDSA87.self,
        operation: operation,
        iterations: iterations,
        warmupIterations: warmupIterations
      )
    }
    print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
  }

  private static func run<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    operation: Operation,
    iterations: Int,
    warmupIterations: Int
  ) throws -> Measurement {
    let seed = deterministicBytes(count: parameters.seedByteCount, seed: 0x65)
    let pair = try parameters.benchmarkKeyPair(seed: seed.span)
    let message = deterministicBytes(count: 1_024, seed: 0xA5)
    let context = deterministicBytes(count: 17, seed: 0xC3)
    var signature = try parameters.benchmarkSign(
      message: message.span,
      context: context.span,
      using: pair,
      entropy: FixedEntropy(byte: 0x73)
    )
    var warmupIteration = 0
    switch operation {
    case .keyGeneration:
      while warmupIteration < warmupIterations {
        _ = try keyGenerationChecksum(parameters, iteration: warmupIteration)
        warmupIteration += 1
      }
    case .signing:
      while warmupIteration < warmupIterations {
        var output = signature.mutableSpan
        try parameters.benchmarkSign(
          message: message.span,
          context: context.span,
          using: pair,
          into: &output
        )
        warmupIteration += 1
      }
    case .verification:
      while warmupIteration < warmupIterations {
        guard
          try parameters.benchmarkVerify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair
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
        checksum &+= try keyGenerationChecksum(parameters, iteration: iteration)
        iteration += 1
      }
    case .signing:
      var iteration = 0
      while iteration < iterations {
        var output = signature.mutableSpan
        try parameters.benchmarkSign(
          message: message.span,
          context: context.span,
          using: pair,
          into: &output
        )
        checksum &+= UInt64(signature[iteration % signature.count])
        iteration += 1
      }
    case .verification:
      var iteration = 0
      while iteration < iterations {
        guard
          try parameters.benchmarkVerify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair
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

  private static func keyGenerationChecksum<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    iteration: Int
  ) throws -> UInt64 {
    let generated = try parameters.benchmarkKeyPair()
    return parameters.benchmarkPublicByte(
      at: iteration % parameters.publicKeyByteCount,
      from: generated
    )
  }

  private static func runValidation(_ arguments: [String]) throws {
    switch arguments[1] {
    case "--memory":
      guard
        arguments.count == 5,
        let parameterSet = ParameterSet(rawValue: arguments[2]),
        let operation = Operation(rawValue: arguments[3]),
        let iterations = Int(arguments[4]),
        iterations > 0
      else {
        throw ArgumentError.invalidArguments
      }
      switch parameterSet {
      case .mlDSA44:
        try runMemoryMeasurement(MLDSA44.self, operation: operation, iterations: iterations)
      case .mlDSA65:
        try runMemoryMeasurement(MLDSA65.self, operation: operation, iterations: iterations)
      case .mlDSA87:
        try runMemoryMeasurement(MLDSA87.self, operation: operation, iterations: iterations)
      }
    case "--fixture":
      guard
        arguments.count == 7,
        let parameterSet = ParameterSet(rawValue: arguments[2])
      else {
        throw ArgumentError.invalidArguments
      }
      switch parameterSet {
      case .mlDSA44:
        try emitFixture(MLDSA44.self, arguments: arguments)
      case .mlDSA65:
        try emitFixture(MLDSA65.self, arguments: arguments)
      case .mlDSA87:
        try emitFixture(MLDSA87.self, arguments: arguments)
      }
    case "--validate":
      guard
        arguments.count == 8,
        let parameterSet = ParameterSet(rawValue: arguments[2])
      else {
        throw ArgumentError.validationFailure
      }
      switch parameterSet {
      case .mlDSA44:
        try validateFixture(MLDSA44.self, arguments: arguments)
      case .mlDSA65:
        try validateFixture(MLDSA65.self, arguments: arguments)
      case .mlDSA87:
        try validateFixture(MLDSA87.self, arguments: arguments)
      }
    case "--verify":
      guard
        arguments.count == 7,
        let parameterSet = ParameterSet(rawValue: arguments[2])
      else {
        throw ArgumentError.invalidArguments
      }
      switch parameterSet {
      case .mlDSA44:
        try verifyFixture(MLDSA44.self, arguments: arguments)
      case .mlDSA65:
        try verifyFixture(MLDSA65.self, arguments: arguments)
      case .mlDSA87:
        try verifyFixture(MLDSA87.self, arguments: arguments)
      }
    default:
      throw ArgumentError.invalidArguments
    }
  }

  private static func emitFixture<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    arguments: [String]
  ) throws {
    let seed = try decodeHex(arguments[3], expectedByteCount: parameters.seedByteCount)
    let message = try decodeHex(arguments[4], expectedByteCount: 64)
    let context = try decodeHex(arguments[5], expectedByteCount: 19)
    let randomizer = try decodeHex(
      arguments[6],
      expectedByteCount: parameters.randomizerByteCount
    )
    let pair = try parameters.benchmarkKeyPair(seed: seed.span)
    let signature = try parameters.benchmarkSign(
      message: message.span,
      context: context.span,
      using: pair,
      entropy: ByteEntropy(bytes: randomizer)
    )
    let publicKey = parameters.benchmarkPublicKeyBytes(from: pair)
    print(
      "FIXTURE,\(encodeHex(publicKey.span)),\(encodeHex(signature.span))"
    )
  }

  private static func validateFixture<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    arguments: [String]
  ) throws {
    let seed = try decodeHex(arguments[3], expectedByteCount: parameters.seedByteCount)
    let expectedPublic = try decodeHex(
      arguments[4],
      expectedByteCount: parameters.publicKeyByteCount
    )
    let signature = try decodeHex(
      arguments[5],
      expectedByteCount: parameters.signatureByteCount
    )
    let message = try decodeHex(arguments[6], expectedByteCount: 64)
    let context = try decodeHex(arguments[7], expectedByteCount: 19)
    let pair = try parameters.benchmarkKeyPair(seed: seed.span)
    let publicKey = parameters.benchmarkPublicKeyBytes(from: pair)
    guard
      equal(publicKey.span, expectedPublic.span),
      try parameters.benchmarkVerify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: pair
      )
    else {
      throw ArgumentError.validationFailure
    }
    print("VALIDATED")
  }

  private static func verifyFixture<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    arguments: [String]
  ) throws {
    let encodedPublic = try decodeHex(
      arguments[3],
      expectedByteCount: parameters.publicKeyByteCount
    )
    let signature = try decodeHex(
      arguments[4],
      expectedByteCount: parameters.signatureByteCount
    )
    let message = try decodeHex(arguments[5], expectedByteCount: 64)
    let context = try decodeHex(arguments[6], expectedByteCount: 19)
    let valid = try parameters.benchmarkVerify(
      signature: signature.span,
      message: message.span,
      context: context.span,
      publicKeyBytes: encodedPublic.span
    )
    print("VERIFIED,\(valid ? 1 : 0)")
  }

  private static func runMemoryMeasurement<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
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
        _ = try memoryKeyGeneration(parameters, iterations: 1)
        probe.start()
        do {
          checksum = try memoryKeyGeneration(parameters, iterations: iterations)
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .signing:
        let seed = deterministicBytes(count: parameters.seedByteCount, seed: 0x65)
        let pair = try parameters.benchmarkKeyPair(seed: seed.span)
        let message = deterministicBytes(count: 1_024, seed: 0xA5)
        let context = deterministicBytes(count: 17, seed: 0xC3)
        var signature = try parameters.benchmarkSign(
          message: message.span,
          context: context.span,
          using: pair,
          entropy: FixedEntropy(byte: 0x73)
        )
        probe.start()
        do {
          checksum = try memorySigning(
            parameters,
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
        let seed = deterministicBytes(count: parameters.seedByteCount, seed: 0x65)
        let pair = try parameters.benchmarkKeyPair(seed: seed.span)
        let message = deterministicBytes(count: 1_024, seed: 0xA5)
        let context = deterministicBytes(count: 17, seed: 0xC3)
        let signature = try parameters.benchmarkSign(
          message: message.span,
          context: context.span,
          using: pair,
          entropy: FixedEntropy(byte: 0x73)
        )
        guard
          try parameters.benchmarkVerify(
            signature: signature.span,
            message: message.span,
            context: context.span,
            using: pair
          )
        else {
          throw ArgumentError.validationFailure
        }
        probe.start()
        do {
          checksum = try memoryVerification(
            parameters,
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

  private static func memoryKeyGeneration<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    iterations: Int
  ) throws -> UInt64 {
    let entropy = FixedEntropy(byte: 0x51)
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let pair = try parameters.benchmarkKeyPair(using: entropy)
      checksum &+= parameters.benchmarkPublicByte(
        at: iteration % parameters.publicKeyByteCount,
        from: pair
      )
      iteration += 1
    }
    return checksum
  }

  private static func memorySigning<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    pair: borrowing Parameters.BenchmarkKeyPair,
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
      try parameters.benchmarkSign(
        message: message.span,
        context: context.span,
        using: pair,
        entropy: entropy,
        into: &output
      )
      checksum &+= UInt64(signature[iteration % signature.count])
      iteration += 1
    }
    return checksum
  }

  private static func memoryVerification<Parameters: MLDSABenchmarkParameterSet>(
    _ parameters: Parameters.Type,
    pair: borrowing Parameters.BenchmarkKeyPair,
    message: borrowing ContiguousArray<UInt8>,
    context: borrowing ContiguousArray<UInt8>,
    signature: borrowing ContiguousArray<UInt8>,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      guard
        try parameters.benchmarkVerify(
          signature: signature.span,
          message: message.span,
          context: context.span,
          using: pair
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
