import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

#if canImport(Darwin)
  import Darwin
#endif

@main
enum TLSHybridBenchmarkCommand {
  private enum Operation: String {
    case clientOffer = "client-offer"
    case serverAccept = "server-accept"
    case roundTrip = "roundtrip"
    case x25519Public = "x25519-public"
    case x25519Shared = "x25519-shared"
  }

  private enum ArgumentError: Error {
    case invalidArguments
    case validationFailure
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
    if arguments.count >= 2 {
      switch arguments[1] {
      case "interop-client-offer":
        guard arguments.count == 2 else { throw ArgumentError.invalidArguments }
        try printInteropClientOffer()
        return
      case "interop-client-complete":
        guard arguments.count == 3 else { throw ArgumentError.invalidArguments }
        try printInteropClientSecret(serverShareHex: arguments[2])
        return
      case "interop-server":
        guard arguments.count == 3 else { throw ArgumentError.invalidArguments }
        try printInteropServerResult(clientShareHex: arguments[2])
        return
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
        return
      default:
        break
      }
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

    _ = try run(operation: operation, iterations: warmupIterations)
    let measurement = try run(operation: operation, iterations: iterations)
    print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
  }

  private static func printInteropClientOffer() throws {
    let client = try makeInteropClient()
    print("CLIENT,\(client.withClientShare { encodeHex($0) })")
  }

  private static func printInteropClientSecret(serverShareHex: String) throws {
    var client = try makeInteropClient()
    let serverShare = try decodeHex(serverShareHex)
    let secret = try client.complete(serverShare: serverShare.span)
    print("SECRET,\(secret.withBorrowedBytes { encodeHex($0) })")
  }

  private static func printInteropServerResult(clientShareHex: String) throws {
    let entropy = RepeatingEntropySource(byte: 0x33)
    var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(using: entropy)
    let clientShare = try decodeHex(clientShareHex)
    let result = try server.accept(clientShare: clientShare.span, using: entropy)
    let serverShare = encodeHex(result.serverShare.span)
    let secret = result.sharedSecret.withBorrowedBytes { encodeHex($0) }
    print("SERVER,\(serverShare),\(secret)")
  }

  private static func makeInteropClient() throws -> TLS13X25519MLKEM768ClientKeyExchange {
    try TLS13X25519MLKEM768ClientKeyExchange.generate(
      mlkemEntropy: RepeatingEntropySource(byte: 0x11),
      x25519Entropy: RepeatingEntropySource(byte: 0x22)
    )
  }

  private static func encodeHex(_ bytes: Span<UInt8>) -> String {
    let alphabet = Array("0123456789abcdef".utf8)
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(bytes.count * 2)
    var index = 0
    while index < bytes.count {
      let byte = bytes[index]
      encoded.append(alphabet[Int(byte >> 4)])
      encoded.append(alphabet[Int(byte & 0x0F)])
      index += 1
    }
    return String(decoding: encoded, as: UTF8.self)
  }

  private static func decodeHex(_ encoded: String) throws -> ContiguousArray<UInt8> {
    let utf8 = ContiguousArray(encoded.utf8)
    guard utf8.count.isMultiple(of: 2) else {
      throw ArgumentError.invalidArguments
    }
    var decoded = ContiguousArray<UInt8>()
    decoded.reserveCapacity(utf8.count / 2)
    var index = 0
    while index < utf8.count {
      guard
        let high = hexNibble(utf8[index]),
        let low = hexNibble(utf8[index + 1])
      else {
        throw ArgumentError.invalidArguments
      }
      decoded.append((high << 4) | low)
      index += 2
    }
    return decoded
  }

  private static func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57:
      return byte - 48
    case 97...102:
      return byte - 87
    default:
      return nil
    }
  }

  private struct RepeatingEntropySource: EntropySource {
    let byte: UInt8

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
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
      case .clientOffer:
        let entropy = RepeatingEntropySource(byte: 0x11)
        probe.start()
        do {
          checksum = try memoryClientOffer(
            entropy: entropy,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .serverAccept:
        let client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
          mlkemEntropy: RepeatingEntropySource(byte: 0x11),
          x25519Entropy: RepeatingEntropySource(byte: 0x22)
        )
        let clientShare = client.clientShare()
        let entropy = RepeatingEntropySource(byte: 0x33)
        probe.start()
        do {
          checksum = try memoryServerAccept(
            clientShare: clientShare,
            entropy: entropy,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .roundTrip:
        let clientEntropy = RepeatingEntropySource(byte: 0x11)
        let serverEntropy = RepeatingEntropySource(byte: 0x33)
        probe.start()
        do {
          checksum = try memoryRoundTrip(
            clientEntropy: clientEntropy,
            serverEntropy: serverEntropy,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .x25519Public:
        let privateKey = try X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x42, count: 32).span
        )
        var output = ContiguousArray<UInt8>(
          repeating: 0,
          count: X25519PublicKey.byteCount
        )
        probe.start()
        do {
          checksum = try memoryX25519Public(
            privateKey: privateKey,
            output: &output,
            iterations: iterations
          )
        } catch {
          probe.stopAndPrint()
          throw error
        }
      case .x25519Shared:
        let privateKey = try X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x42, count: 32).span
        )
        let peerPrivateKey = try X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x24, count: 32).span
        )
        let peerPublicKey = peerPrivateKey.publicKey()
        var output = ContiguousArray<UInt8>(
          repeating: 0,
          count: X25519SharedSecret.byteCount
        )
        probe.start()
        do {
          checksum = try memoryX25519Shared(
            privateKey: privateKey,
            peerPublicKey: peerPublicKey,
            output: &output,
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

  private static func memoryClientOffer(
    entropy: borrowing RepeatingEntropySource,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
        mlkemEntropy: copy entropy,
        x25519Entropy: copy entropy
      )
      checksum &+= client.withClientShare { share in
        UInt64(share[iteration % share.count])
      }
      iteration += 1
    }
    return checksum
  }

  private static func memoryServerAccept(
    clientShare: borrowing OwnedBytes,
    entropy: borrowing RepeatingEntropySource,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
        using: copy entropy
      )
      let result = try server.accept(
        clientShare: clientShare.span,
        using: copy entropy
      )
      checksum &+= UInt64(result.serverShare[iteration % result.serverShare.count])
      checksum &+= result.sharedSecret.withBorrowedBytes { secret in
        UInt64(secret[iteration % secret.count])
      }
      iteration += 1
    }
    return checksum
  }

  private static func memoryRoundTrip(
    clientEntropy: borrowing RepeatingEntropySource,
    serverEntropy: borrowing RepeatingEntropySource,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
        mlkemEntropy: copy clientEntropy,
        x25519Entropy: copy clientEntropy
      )
      var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
        using: copy serverEntropy
      )
      let clientShare = client.clientShare()
      let serverResult = try server.accept(
        clientShare: clientShare.span,
        using: copy serverEntropy
      )
      let clientSecret = try client.complete(
        serverShare: serverResult.serverShare.span
      )
      checksum &+= UInt64(
        serverResult.serverShare[iteration % serverResult.serverShare.count]
      )
      checksum &+= clientSecret.withBorrowedBytes { secret in
        UInt64(secret[iteration % secret.count])
      }
      iteration += 1
    }
    return checksum
  }

  private static func memoryX25519Public(
    privateKey: borrowing X25519PrivateKey,
    output: inout ContiguousArray<UInt8>,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var destination = output.mutableSpan
      try privateKey.publicKey(into: &destination)
      checksum &+= UInt64(output[iteration % output.count])
      iteration += 1
    }
    return checksum
  }

  private static func memoryX25519Shared(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey,
    output: inout ContiguousArray<UInt8>,
    iterations: Int
  ) throws -> UInt64 {
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var destination = output.mutableSpan
      try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKeyBytes: peerPublicKey.span,
        into: &destination
      )
      checksum &+= UInt64(output[iteration % output.count])
      iteration += 1
    }
    return checksum
  }

  @inline(never)
  private static func run(
    operation: Operation,
    iterations: Int
  ) throws -> Measurement {
    switch operation {
    case .clientOffer:
      return try runClientOffer(iterations: iterations)
    case .serverAccept:
      return try runServerAccept(iterations: iterations)
    case .roundTrip:
      return try runRoundTrip(iterations: iterations)
    case .x25519Public:
      return try runX25519Public(iterations: iterations)
    case .x25519Shared:
      return try runX25519Shared(iterations: iterations)
    }
  }

  private static func runClientOffer(iterations: Int) throws -> Measurement {
    let entropy = SystemEntropySource()
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
        mlkemEntropy: entropy,
        x25519Entropy: entropy
      )
      checksum &+= client.withClientShare { share in
        UInt64(share[iteration % share.count])
      }
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runServerAccept(iterations: Int) throws -> Measurement {
    let entropy = SystemEntropySource()
    let client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
      mlkemEntropy: entropy,
      x25519Entropy: entropy
    )
    let clientShare = client.clientShare()
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
        using: entropy
      )
      let result = try server.accept(
        clientShare: clientShare.span,
        using: entropy
      )
      checksum &+= UInt64(
        result.serverShare[iteration % result.serverShare.count]
      )
      checksum &+= result.sharedSecret.withBorrowedBytes { secret in
        UInt64(secret[iteration % secret.count])
      }
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runRoundTrip(iterations: Int) throws -> Measurement {
    let entropy = SystemEntropySource()
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
        mlkemEntropy: entropy,
        x25519Entropy: entropy
      )
      var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
        using: entropy
      )
      let clientShare = client.clientShare()
      let serverResult = try server.accept(
        clientShare: clientShare.span,
        using: entropy
      )
      let clientSecret = try client.complete(
        serverShare: serverResult.serverShare.span
      )
      checksum &+= UInt64(
        serverResult.serverShare[iteration % serverResult.serverShare.count]
      )
      checksum &+= clientSecret.withBorrowedBytes { secret in
        UInt64(secret[iteration % secret.count])
      }
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runX25519Public(iterations: Int) throws -> Measurement {
    let privateKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x42, count: 32).span
    )
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let publicKey = privateKey.publicKey()
      checksum &+= UInt64(publicKey.span[iteration % publicKey.span.count])
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runX25519Shared(iterations: Int) throws -> Measurement {
    let privateKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x42, count: 32).span
    )
    let peerPrivateKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x24, count: 32).span
    )
    let peerPublicKey = peerPrivateKey.publicKey()
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      let secret = try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKey: peerPublicKey
      )
      checksum &+= secret.withBorrowedBytes { bytes in
        UInt64(bytes[iteration % bytes.count])
      }
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
}
