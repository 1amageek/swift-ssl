import SwiftSSL

@main
enum MLKEMBenchmarkCommand {
  private enum ParameterSet: String {
    case mlKEM768 = "768"
    case mlKEM1024 = "1024"
  }

  private enum Operation: String {
    case keyGeneration = "keygen"
    case encapsulation = "encap"
    case decapsulation = "decap"
  }

  private enum ArgumentError: Error {
    case invalidArguments
    case validationFailure
  }

  private struct FixedEntropy: EntropySource {
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

  private struct Measurement {
    let nanoseconds: Int64
    let checksum: UInt64
  }

  static func main() throws {
    let arguments = CommandLine.arguments
    if arguments.count > 1, arguments[1].hasPrefix("--") {
      try runValidationCommand(arguments)
      return
    }
    guard
      arguments.count == 5,
      let parameters = ParameterSet(rawValue: arguments[1]),
      let operation = Operation(rawValue: arguments[2]),
      let iterations = Int(arguments[3]),
      let warmupIterations = Int(arguments[4]),
      iterations > 0,
      warmupIterations >= 0
    else {
      throw ArgumentError.invalidArguments
    }

    _ = try run(
      parameters: parameters,
      operation: operation,
      iterations: warmupIterations
    )
    let measurement = try run(
      parameters: parameters,
      operation: operation,
      iterations: iterations
    )
    print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
  }

  private static func runValidationCommand(_ arguments: [String]) throws {
    guard arguments.count >= 3, let parameters = ParameterSet(rawValue: arguments[2]) else {
      throw ArgumentError.invalidArguments
    }
    switch arguments[1] {
    case "--fixture":
      guard arguments.count == 5 else {
        throw ArgumentError.invalidArguments
      }
      let seed = try decodeHex(arguments[3], expectedByteCount: 64)
      let message = try decodeHex(arguments[4], expectedByteCount: 32)
      switch parameters {
      case .mlKEM768:
        try emitMLKEM768Fixture(seed: seed, message: message)
      case .mlKEM1024:
        try emitMLKEM1024Fixture(seed: seed, message: message)
      }
    case "--validate":
      guard arguments.count == 7 else {
        throw ArgumentError.invalidArguments
      }
      let seed = try decodeHex(arguments[3], expectedByteCount: 64)
      let publicKey = try decodeHex(
        arguments[4],
        expectedByteCount: parameters == .mlKEM768
          ? MLKEM768.PublicKey.byteCount
          : MLKEM1024.PublicKey.byteCount
      )
      let ciphertext = try decodeHex(
        arguments[5],
        expectedByteCount: parameters == .mlKEM768
          ? MLKEM768.Encapsulation.byteCount
          : MLKEM1024.Encapsulation.byteCount
      )
      let expectedSecret = try decodeHex(arguments[6], expectedByteCount: 32)
      switch parameters {
      case .mlKEM768:
        try validateMLKEM768Fixture(
          seed: seed,
          publicKey: publicKey,
          ciphertext: ciphertext,
          expectedSecret: expectedSecret
        )
      case .mlKEM1024:
        try validateMLKEM1024Fixture(
          seed: seed,
          publicKey: publicKey,
          ciphertext: ciphertext,
          expectedSecret: expectedSecret
        )
      }
      print("VALIDATED")
    case "--decap":
      guard arguments.count == 5 else {
        throw ArgumentError.invalidArguments
      }
      let seed = try decodeHex(arguments[3], expectedByteCount: 64)
      let ciphertext = try decodeHex(
        arguments[4],
        expectedByteCount: parameters == .mlKEM768
          ? MLKEM768.Encapsulation.byteCount
          : MLKEM1024.Encapsulation.byteCount
      )
      switch parameters {
      case .mlKEM768:
        let pair = try MLKEM768.generateKeyPair(using: FixedEntropy(bytes: seed))
        let encapsulation = try MLKEM768.Encapsulation(bytes: ciphertext.span)
        let secret = try MLKEM768.decapsulate(encapsulation, using: pair.privateKey)
        print("SECRET,\(secret.withBorrowedBytes { encodeHex($0) })")
      case .mlKEM1024:
        let pair = try MLKEM1024.generateKeyPair(using: FixedEntropy(bytes: seed))
        let encapsulation = try MLKEM1024.Encapsulation(bytes: ciphertext.span)
        let secret = try MLKEM1024.decapsulate(encapsulation, using: pair.privateKey)
        print("SECRET,\(secret.withBorrowedBytes { encodeHex($0) })")
      }
    default:
      throw ArgumentError.invalidArguments
    }
  }

  private static func emitMLKEM768Fixture(
    seed: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>
  ) throws {
    let pair = try MLKEM768.generateKeyPair(using: FixedEntropy(bytes: seed))
    let result = try MLKEM768.encapsulate(
      to: pair.publicKey,
      using: FixedEntropy(bytes: message)
    )
    print(
      "FIXTURE,\(encodeHex(pair.publicKey.span)),"
        + "\(encodeHex(result.encapsulation.span)),"
        + "\(result.sharedSecret.withBorrowedBytes { encodeHex($0) })"
    )
  }

  private static func emitMLKEM1024Fixture(
    seed: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>
  ) throws {
    let pair = try MLKEM1024.generateKeyPair(using: FixedEntropy(bytes: seed))
    let result = try MLKEM1024.encapsulate(
      to: pair.publicKey,
      using: FixedEntropy(bytes: message)
    )
    print(
      "FIXTURE,\(encodeHex(pair.publicKey.span)),"
        + "\(encodeHex(result.encapsulation.span)),"
        + "\(result.sharedSecret.withBorrowedBytes { encodeHex($0) })"
    )
  }

  private static func validateMLKEM768Fixture(
    seed: ContiguousArray<UInt8>,
    publicKey: ContiguousArray<UInt8>,
    ciphertext: ContiguousArray<UInt8>,
    expectedSecret: ContiguousArray<UInt8>
  ) throws {
    let pair = try MLKEM768.generateKeyPair(using: FixedEntropy(bytes: seed))
    guard copy(pair.publicKey.span) == publicKey else {
      throw ArgumentError.validationFailure
    }
    let encapsulation = try MLKEM768.Encapsulation(bytes: ciphertext.span)
    let secret = try MLKEM768.decapsulate(encapsulation, using: pair.privateKey)
    guard secret.withBorrowedBytes({ copy($0) }) == expectedSecret else {
      throw ArgumentError.validationFailure
    }
  }

  private static func validateMLKEM1024Fixture(
    seed: ContiguousArray<UInt8>,
    publicKey: ContiguousArray<UInt8>,
    ciphertext: ContiguousArray<UInt8>,
    expectedSecret: ContiguousArray<UInt8>
  ) throws {
    let pair = try MLKEM1024.generateKeyPair(using: FixedEntropy(bytes: seed))
    guard copy(pair.publicKey.span) == publicKey else {
      throw ArgumentError.validationFailure
    }
    let encapsulation = try MLKEM1024.Encapsulation(bytes: ciphertext.span)
    let secret = try MLKEM1024.decapsulate(encapsulation, using: pair.privateKey)
    guard secret.withBorrowedBytes({ copy($0) }) == expectedSecret else {
      throw ArgumentError.validationFailure
    }
  }

  @inline(never)
  private static func run(
    parameters: ParameterSet,
    operation: Operation,
    iterations: Int
  ) throws -> Measurement {
    switch (parameters, operation) {
    case (.mlKEM768, .keyGeneration):
      return try runMLKEM768KeyGeneration(iterations: iterations)
    case (.mlKEM768, .encapsulation):
      return try runMLKEM768Encapsulation(iterations: iterations)
    case (.mlKEM768, .decapsulation):
      return try runMLKEM768Decapsulation(iterations: iterations)
    case (.mlKEM1024, .keyGeneration):
      return try runMLKEM1024KeyGeneration(iterations: iterations)
    case (.mlKEM1024, .encapsulation):
      return try runMLKEM1024Encapsulation(iterations: iterations)
    case (.mlKEM1024, .decapsulation):
      return try runMLKEM1024Decapsulation(iterations: iterations)
    }
  }

  private static func runMLKEM768KeyGeneration(iterations: Int) throws -> Measurement {
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let pair = try MLKEM768.generateKeyPair()
      checksum &+= UInt64(pair.publicKey.span[iteration % MLKEM768.PublicKey.byteCount])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runMLKEM768Encapsulation(iterations: Int) throws -> Measurement {
    let pair = try MLKEM768.generateKeyPair()
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM768.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM768.sharedSecretByteCount
    )
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var encapsulationOutput = encapsulation.mutableSpan
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM768.encapsulate(
        to: pair.publicKey,
        into: &encapsulationOutput,
        sharedSecret: &secretOutput
      )
      checksum &+= UInt64(encapsulation[iteration % encapsulation.count])
      checksum &+= UInt64(sharedSecret[iteration % sharedSecret.count])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runMLKEM768Decapsulation(iterations: Int) throws -> Measurement {
    let pair = try MLKEM768.generateKeyPair()
    let encapsulated = try MLKEM768.encapsulate(to: pair.publicKey)
    let expected = encapsulated.sharedSecret.withBorrowedBytes { copy($0) }
    let probe = try MLKEM768.decapsulate(
      encapsulated.encapsulation,
      using: pair.privateKey
    )
    guard probe.withBorrowedBytes({ copy($0) }) == expected else {
      throw ArgumentError.validationFailure
    }

    let clock = ContinuousClock()
    let start = clock.now
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM768.sharedSecretByteCount
    )
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM768.decapsulate(
        encapsulated.encapsulation.span,
        using: pair.privateKey,
        into: &secretOutput
      )
      checksum &+= UInt64(sharedSecret[iteration % sharedSecret.count])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runMLKEM1024KeyGeneration(iterations: Int) throws -> Measurement {
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let pair = try MLKEM1024.generateKeyPair()
      checksum &+= UInt64(pair.publicKey.span[iteration % MLKEM1024.PublicKey.byteCount])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runMLKEM1024Encapsulation(iterations: Int) throws -> Measurement {
    let pair = try MLKEM1024.generateKeyPair()
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.sharedSecretByteCount
    )
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var encapsulationOutput = encapsulation.mutableSpan
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM1024.encapsulate(
        to: pair.publicKey,
        into: &encapsulationOutput,
        sharedSecret: &secretOutput
      )
      checksum &+= UInt64(encapsulation[iteration % encapsulation.count])
      checksum &+= UInt64(sharedSecret[iteration % sharedSecret.count])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runMLKEM1024Decapsulation(iterations: Int) throws -> Measurement {
    let pair = try MLKEM1024.generateKeyPair()
    let encapsulated = try MLKEM1024.encapsulate(to: pair.publicKey)
    let expected = encapsulated.sharedSecret.withBorrowedBytes { copy($0) }
    let probe = try MLKEM1024.decapsulate(
      encapsulated.encapsulation,
      using: pair.privateKey
    )
    guard probe.withBorrowedBytes({ copy($0) }) == expected else {
      throw ArgumentError.validationFailure
    }

    let clock = ContinuousClock()
    let start = clock.now
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.sharedSecretByteCount
    )
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM1024.decapsulate(
        encapsulated.encapsulation.span,
        using: pair.privateKey,
        into: &secretOutput
      )
      checksum &+= UInt64(sharedSecret[iteration % sharedSecret.count])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  @inline(__always)
  private static func measurement(
    since start: ContinuousClock.Instant,
    clock: ContinuousClock,
    checksum: UInt64
  ) -> Measurement {
    let elapsed = start.duration(to: clock.now).components
    return Measurement(
      nanoseconds: elapsed.seconds * 1_000_000_000
        + elapsed.attoseconds / 1_000_000_000,
      checksum: checksum
    )
  }

  private static func copy(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
      result.append(bytes[index])
      index += 1
    }
    return result
  }

  private static func decodeHex(
    _ value: String,
    expectedByteCount: Int
  ) throws -> ContiguousArray<UInt8> {
    let bytes = value.utf8
    guard bytes.count == expectedByteCount * 2 else {
      throw ArgumentError.invalidArguments
    }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(expectedByteCount)
    var index = bytes.startIndex
    while index < bytes.endIndex {
      let next = bytes.index(after: index)
      guard
        next < bytes.endIndex,
        let high = hexNibble(bytes[index]),
        let low = hexNibble(bytes[next])
      else {
        throw ArgumentError.invalidArguments
      }
      result.append((high << 4) | low)
      index = bytes.index(after: next)
    }
    return result
  }

  private static func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57:
      return byte - 48
    case 65...70:
      return byte - 55
    case 97...102:
      return byte - 87
    default:
      return nil
    }
  }

  private static func encodeHex(_ bytes: Span<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var result = String()
    result.reserveCapacity(bytes.count * 2)
    var index = 0
    while index < bytes.count {
      let byte = bytes[index]
      result.append(Character(UnicodeScalar(digits[Int(byte >> 4)])))
      result.append(Character(UnicodeScalar(digits[Int(byte & 0x0F)])))
      index += 1
    }
    return result
  }
}
