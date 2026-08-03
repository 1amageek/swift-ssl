import SSLCore
import SSLCrypto

#if canImport(Darwin)
  import Darwin
#endif

@main
enum HPKEBenchmarkCommand {
  private enum Operation: String {
    case firstSeal = "first-seal"
    case firstOpen = "first-open"
    case recipientSetup = "recipient-setup"
    case x25519Shared = "x25519-shared"
    case p256SenderSetup = "p256-sender-setup"
    case p256RecipientSetup = "p256-recipient-setup"
    case p256Shared = "p256-shared"
    case p256EncodedShared = "p256-encoded-shared"
  }

  private enum BenchmarkError: Error {
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

  #if canImport(Darwin)
    private struct AllocationProbe {
      let start: @convention(c) () -> Void
      let stopAndPrint: @convention(c) () -> Void

      init() throws {
        // The dynamic loader owns both function addresses for the process
        // lifetime. They are invoked synchronously and never cross a Sendable
        // boundary, so the unsafe conversion cannot outlive its code owner.
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
          throw BenchmarkError.validationFailure
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
    if arguments.count == 4, arguments[1] == "validate",
      let payloadByteCount = Int(arguments[2]),
      let authenticatedDataByteCount = Int(arguments[3]),
      payloadByteCount > 0,
      authenticatedDataByteCount >= 0
    {
      try validate(
        payloadByteCount: payloadByteCount,
        authenticatedDataByteCount: authenticatedDataByteCount
      )
      return
    }
    if arguments.count > 1, arguments[1] == "--memory" {
      try runMemoryMeasurement(arguments)
      return
    }
    guard arguments.count == 6,
      let operation = Operation(rawValue: arguments[1]),
      let payloadByteCount = Int(arguments[2]),
      let authenticatedDataByteCount = Int(arguments[3]),
      let iterations = Int(arguments[4]),
      let warmupIterations = Int(arguments[5]),
      payloadByteCount > 0,
      authenticatedDataByteCount >= 0,
      iterations > 0,
      warmupIterations >= 0
    else {
      throw BenchmarkError.invalidArguments
    }

    _ = try run(
      operation: operation,
      payloadByteCount: payloadByteCount,
      authenticatedDataByteCount: authenticatedDataByteCount,
      iterations: warmupIterations
    )
    let measurement = try run(
      operation: operation,
      payloadByteCount: payloadByteCount,
      authenticatedDataByteCount: authenticatedDataByteCount,
      iterations: iterations
    )
    print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
  }

  private static func validate(
    payloadByteCount: Int,
    authenticatedDataByteCount: Int
  ) throws {
    let recipientScalar = ContiguousArray<UInt8>(repeating: 0x41, count: 32)
    let ephemeralScalar = ContiguousArray<UInt8>(repeating: 0x53, count: 32)
    let recipientKey = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: recipientScalar.span)
    )
    let info = deterministicBytes(count: 77, seed: 0x20)
    let plaintext = deterministicBytes(count: payloadByteCount, seed: 0x30)
    let authenticatedData = deterministicBytes(
      count: authenticatedDataByteCount,
      seed: 0x40
    )
    let setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientKey.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: ephemeralScalar)
    )
    let encapsulation = setup.encapsulation
    var sender = setup.takeContext()
    var ciphertext = ContiguousArray<UInt8>(
      repeating: 0,
      count: payloadByteCount + HPKEAEAD.tagByteCount
    )
    var ciphertextDestination = ciphertext.mutableSpan
    try sender.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span,
      into: &ciphertextDestination
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: encapsulation.span,
      recipientKeyPair: recipientKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var recovered = ContiguousArray<UInt8>(repeating: 0, count: payloadByteCount)
    var recoveredDestination = recovered.mutableSpan
    try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: authenticatedData.span,
      into: &recoveredDestination
    )
    guard recovered == plaintext else { throw BenchmarkError.validationFailure }
    print("ENCAPSULATION,\(hex(encapsulation.span))")
    print("CIPHERTEXT,\(hex(ciphertext.span))")
    print("PLAINTEXT,\(hex(recovered.span))")
  }

  private static func runMemoryMeasurement(_ arguments: [String]) throws {
    guard arguments.count == 6,
      let operation = Operation(rawValue: arguments[2]),
      let payloadByteCount = Int(arguments[3]),
      let authenticatedDataByteCount = Int(arguments[4]),
      let iterations = Int(arguments[5]),
      payloadByteCount > 0,
      authenticatedDataByteCount >= 0,
      iterations > 0
    else {
      throw BenchmarkError.invalidArguments
    }
    #if canImport(Darwin)
      _ = try run(
        operation: operation,
        payloadByteCount: payloadByteCount,
        authenticatedDataByteCount: authenticatedDataByteCount,
        iterations: 1
      )
      let probe = try AllocationProbe()
      probe.start()
      do {
        let measurement = try run(
          operation: operation,
          payloadByteCount: payloadByteCount,
          authenticatedDataByteCount: authenticatedDataByteCount,
          iterations: iterations
        )
        probe.stopAndPrint()
        print("MEMORY_CHECKSUM,\(iterations),\(measurement.checksum)")
      } catch {
        probe.stopAndPrint()
        throw error
      }
    #else
      throw BenchmarkError.validationFailure
    #endif
  }

  @inline(never)
  private static func run(
    operation: Operation,
    payloadByteCount: Int,
    authenticatedDataByteCount: Int,
    iterations: Int
  ) throws -> Measurement {
    let recipientScalar = ContiguousArray<UInt8>(repeating: 0x41, count: 32)
    let ephemeralScalar = ContiguousArray<UInt8>(repeating: 0x53, count: 32)
    if operation == .p256SenderSetup
      || operation == .p256RecipientSetup
      || operation == .p256Shared
      || operation == .p256EncodedShared
    {
      let recipientKey = P256KeyPair(
        privateKey: try P256PrivateKey(bytes: recipientScalar.span)
      )
      let ephemeralKey = P256KeyPair(
        privateKey: try P256PrivateKey(bytes: ephemeralScalar.span)
      )
      if operation == .p256Shared || operation == .p256EncodedShared {
        var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: 32)
        let clock = ContinuousClock()
        let start = clock.now
        var checksum: UInt64 = 0
        var iteration = 0
        while iteration < iterations {
          var destination = sharedSecret.mutableSpan
          if operation == .p256Shared {
            try P256KeyAgreement.sharedSecret(
              privateKey: recipientKey.privateKey,
              peerPublicKey: ephemeralKey.publicKey,
              into: &destination
            )
          } else {
            try P256KeyAgreement.sharedSecret(
              privateKey: recipientKey.privateKey,
              peerPublicKeyBytes: ephemeralKey.publicKey.span,
              into: &destination
            )
          }
          checksum &+= UInt64(sharedSecret[iteration & 31])
          iteration += 1
        }
        let elapsed = start.duration(to: clock.now).components
        return Measurement(
          nanoseconds: elapsed.seconds * 1_000_000_000
            + elapsed.attoseconds / 1_000_000_000,
          checksum: checksum
        )
      }
      let info = deterministicBytes(count: 77, seed: 0x20)
      let clock = ContinuousClock()
      let start = clock.now
      var checksum: UInt64 = 0
      var iteration = 0
      while iteration < iterations {
        if operation == .p256SenderSetup {
          let setup = try HPKEP256.setupBaseSender(
            recipientPublicKeyBytes: recipientKey.publicKey.span,
            info: info.span,
            kdf: .sha256,
            aead: .aes128GCM,
            using: FixedEntropy(bytes: ephemeralScalar)
          )
          checksum &+= UInt64(setup.encapsulation.span.count)
        } else {
          let context = try HPKEP256.setupBaseRecipient(
            encapsulation: ephemeralKey.publicKey.span,
            recipientKeyPair: recipientKey,
            info: info.span,
            kdf: .sha256,
            aead: .aes128GCM
          )
          checksum &+= context.sequenceNumber &+ 1
        }
        iteration += 1
      }
      let elapsed = start.duration(to: clock.now).components
      return Measurement(
        nanoseconds: elapsed.seconds * 1_000_000_000
          + elapsed.attoseconds / 1_000_000_000,
        checksum: checksum
      )
    }
    let recipientKey = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: recipientScalar.span)
    )
    let recipientPublicKey = recipientKey.publicKey
    if operation == .x25519Shared {
      let privateKey = try X25519PrivateKey(bytes: ephemeralScalar.span)
      var sharedSecret = ContiguousArray<UInt8>(repeating: 0, count: 32)
      let clock = ContinuousClock()
      let start = clock.now
      var checksum: UInt64 = 0
      var iteration = 0
      while iteration < iterations {
        var destination = sharedSecret.mutableSpan
        try X25519.sharedSecret(
          privateKey: privateKey,
          peerPublicKey: recipientPublicKey,
          into: &destination
        )
        checksum &+= UInt64(sharedSecret[iteration & 31])
        iteration += 1
      }
      let elapsed = start.duration(to: clock.now).components
      return Measurement(
        nanoseconds: elapsed.seconds * 1_000_000_000
          + elapsed.attoseconds / 1_000_000_000,
        checksum: checksum
      )
    }
    let info = deterministicBytes(count: 77, seed: 0x20)
    let plaintext = deterministicBytes(count: payloadByteCount, seed: 0x30)
    let authenticatedData = deterministicBytes(
      count: authenticatedDataByteCount,
      seed: 0x40
    )
    var ciphertext = ContiguousArray<UInt8>(
      repeating: 0,
      count: payloadByteCount + HPKEAEAD.tagByteCount
    )
    var recovered = ContiguousArray<UInt8>(repeating: 0, count: payloadByteCount)
    let fixtureSetup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPublicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: ephemeralScalar)
    )
    let encapsulation = fixtureSetup.encapsulation
    var fixtureContext = fixtureSetup.takeContext()
    var fixtureDestination = ciphertext.mutableSpan
    try fixtureContext.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span,
      into: &fixtureDestination
    )

    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      switch operation {
      case .firstSeal:
        let setup = try HPKEX25519.setupBaseSender(
          recipientPublicKey: recipientPublicKey,
          info: info.span,
          kdf: .sha256,
          aead: .aes128GCM,
          using: FixedEntropy(bytes: ephemeralScalar)
        )
        var context = setup.takeContext()
        var destination = ciphertext.mutableSpan
        try context.seal(
          plaintext: plaintext.span,
          authenticatedData: authenticatedData.span,
          into: &destination
        )
        checksum &+= UInt64(ciphertext[iteration % ciphertext.count])
      case .firstOpen:
        var context = try HPKEX25519.setupBaseRecipient(
          encapsulation: encapsulation.span,
          recipientKeyPair: recipientKey,
          info: info.span,
          kdf: .sha256,
          aead: .aes128GCM
        )
        var destination = recovered.mutableSpan
        try context.open(
          ciphertext: ciphertext.span,
          authenticatedData: authenticatedData.span,
          into: &destination
        )
        checksum &+= UInt64(recovered[iteration % recovered.count])
      case .recipientSetup:
        let context = try HPKEX25519.setupBaseRecipient(
          encapsulation: encapsulation.span,
          recipientKeyPair: recipientKey,
          info: info.span,
          kdf: .sha256,
          aead: .aes128GCM
        )
        checksum &+= context.sequenceNumber &+ 1
      case .x25519Shared, .p256SenderSetup, .p256RecipientSetup, .p256Shared,
        .p256EncodedShared:
        preconditionFailure("X25519 is measured before HPKE fixture construction")
      }
      iteration += 1
    }
    let elapsed = start.duration(to: clock.now).components
    return Measurement(
      nanoseconds: elapsed.seconds * 1_000_000_000
        + elapsed.attoseconds / 1_000_000_000,
      checksum: checksum
    )
  }

  private static func deterministicBytes(
    count: Int,
    seed: UInt8
  ) -> ContiguousArray<UInt8> {
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(count)
    var index = 0
    while index < count {
      bytes.append(seed &+ UInt8(truncatingIfNeeded: index &* 29))
      index += 1
    }
    return bytes
  }

  private static func hex(_ bytes: Span<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var result = String()
    result.reserveCapacity(bytes.count * 2)
    var index = 0
    while index < bytes.count {
      let byte = bytes[index]
      result.unicodeScalars.append(UnicodeScalar(digits[Int(byte >> 4)]))
      result.unicodeScalars.append(UnicodeScalar(digits[Int(byte & 0x0f)]))
      index += 1
    }
    return result
  }
}
