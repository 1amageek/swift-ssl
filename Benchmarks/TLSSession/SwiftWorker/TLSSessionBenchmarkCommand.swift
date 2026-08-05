import SSLCore
import SSLCrypto
import SSLTLS
import SSLX509

@main
enum TLSSessionBenchmarkCommand {
  private enum Operation: String {
    case ticket = "ticket"
    case resumption = "resumption"
  }

  private enum ArgumentError: Error {
    case invalidArguments
    case invalidResult
  }

  private struct Measurement {
    let nanoseconds: Int64
    let checksum: UInt64
  }

  static func main() throws {
    let arguments = CommandLine.arguments
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

  private static func run(
    operation: Operation,
    iterations: Int
  ) throws -> Measurement {
    switch operation {
    case .ticket:
      return try runTicket(iterations: iterations)
    case .resumption:
      return try runResumption(iterations: iterations)
    }
  }

  private static func runTicket(iterations: Int) throws -> Measurement {
    let certificate = deterministicCertificate()
    let validator = try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [try X509Certificate(der: certificate.span)]
    )
    let instant = try VerificationInstant(secondsSinceUnixEpoch: 1_720_000_000, nanoseconds: 0)
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var client = try TLS13ClientHandshake(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        ),
        certificateValidator: validator,
        verificationInstant: instant
      )
      let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
      var server = try TLS13ServerHandshake(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x22, count: 32).span
        ),
        certificateDER: certificate.span,
        signingKey: TLS13SigningKey(ed25519: signingKey),
        verificationInstant: instant
      )
      let clientHello = try client.start()
      let serverFlight = try server.receive(clientHello.bytes.span)
      let clientFinished = try client.receive(serverFlight.bytes.span)
      _ = try server.receive(clientFinished.bytes.span)
      let issued = try server.sendNewSessionTicket(
        lifetime: 3_600,
        ageAdd: 7,
        ticketNonce: nonce.span,
        ticket: ticket.span,
        issuedAt: instant
      )
      let state = try client.receiveNewSessionTicket(
        issued.output.bytes.span,
        receivedAt: instant
      )
      checksum &+= UInt64(issued.output.bytes[iteration % issued.output.bytes.count])
      _ = state
      checksum &+= UInt64(ticket.count)
      iteration += 1
    }
    return measurement(since: start, clock: clock, checksum: checksum)
  }

  private static func runResumption(iterations: Int) throws -> Measurement {
    let certificate = deterministicCertificate()
    let validator = try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [try X509Certificate(der: certificate.span)]
    )
    let issuedAt = try VerificationInstant(secondsSinceUnixEpoch: 1_720_000_000, nanoseconds: 0)
    let receivedAt = try VerificationInstant(secondsSinceUnixEpoch: 1_720_000_001, nanoseconds: 0)
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let masterSecret = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    let clock = ContinuousClock()
    let start = clock.now
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      var serverState = try TLS13ResumptionState(
        ticket: ticket.span,
        ticketNonce: nonce.span,
        resumptionMasterSecret: masterSecret.span,
        cipherSuite: .aes128GCM_SHA256,
        issuedAt: issuedAt,
        lifetime: 3_600,
        ageAdd: 7
      )
      let serverPSK = try serverState.consumePSK()
      let clientState = try TLS13ResumptionState(
        ticket: ticket.span,
        ticketNonce: nonce.span,
        resumptionMasterSecret: masterSecret.span,
        cipherSuite: .aes128GCM_SHA256,
        issuedAt: issuedAt,
        lifetime: 3_600,
        ageAdd: 7
      )
      var client = try TLS13ClientHandshake(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        ),
        certificateValidator: validator,
        verificationInstant: issuedAt,
        resumptionState: consume clientState
      )
      var server = try serverPSK.withBorrowedBytes { psk in
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        return try TLS13ServerHandshake(
          random: ContiguousArray(repeating: 0x02, count: 32).span,
          ephemeralKey: X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
          ),
          certificateDER: certificate.span,
          signingKey: TLS13SigningKey(ed25519: signingKey),
          verificationInstant: receivedAt,
          resumptionIdentity: ticket.span,
          resumptionPSK: psk,
          resumptionIssuedAt: issuedAt,
          resumptionLifetime: 3_600,
          resumptionAgeAdd: 7
        )
      }
      let clientHello = try client.start()
      let serverFlight = try server.receive(clientHello.bytes.span)
      let clientFinished = try client.receive(serverFlight.bytes.span)
      let serverFinished = try server.receive(clientFinished.bytes.span)
      guard client.isEstablished, server.isEstablished else {
        throw ArgumentError.invalidResult
      }
      if serverFinished.bytes.count == 0 {
        checksum &+= 1
      } else {
        checksum &+= UInt64(serverFinished.bytes[iteration % serverFinished.bytes.count])
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

  private static func deterministicSeed() -> ContiguousArray<UInt8> {
    bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  }

  private static func deterministicCertificate() -> ContiguousArray<UInt8> {
    bytes(
      "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a"
        + "170d3235303130313030303030305a3000302a300506032b6570032100"
        + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        + "300506032b6570034100"
        + "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b"
        + "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
    )
  }

  private static func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }
}
