import SSLCore
import SSLDTLS
import XCTest

final class DTLSServerRetransmissionTests: XCTestCase {
  func testHandshakeCoreDistinguishesInitialAndVerifiedClientHelloRetransmissions() throws {
    var handshake = makeHandshake()
    let initial = try makeClientHello(cookie: [])
    let verified = try makeClientHello(cookie: [0xA1, 0xB2])
    let initialHeader = makeHeader(sequence: 0, body: initial)
    let verifiedHeader = makeHeader(sequence: 1, body: verified)

    guard case .needCookie = try handshake.ingestClientHello(
      header: initialHeader,
      body: initial
    ) else {
      return XCTFail("The initial ClientHello must request a cookie")
    }

    let helloVerifyRequestBody: [UInt8] = [0xFE, 0xFD, 0x02, 0xA1, 0xB2]
    let firstHelloVerifyRequest = try handshake.emitHelloVerifyRequest(
      helloVerifyRequestBody: helloVerifyRequestBody
    )

    guard case .verifyCookie = try handshake.ingestClientHello(
      header: verifiedHeader,
      body: verified
    ) else {
      return XCTFail("The cookie-bearing ClientHello must be verified")
    }

    _ = try handshake.serverFlight(
      acceptingCookieFrom: try DTLSClientHello.decode(from: verified),
      rawMessage: try DTLSHandshakeHeader.encodeMessage(
        type: .clientHello,
        messageSeq: 1,
        body: verified
      ),
      cookieValid: true,
      selectedSuite: .ecdheEcdsaWithAes128GcmSha256,
      inputs: makeServerFlightInputs()
    )

    guard case .needCookie = try handshake.ingestClientHello(
      header: initialHeader,
      body: initial
    ) else {
      return XCTFail("A delayed initial ClientHello must retransmit only the HVR")
    }
    XCTAssertEqual(
      try handshake.emitHelloVerifyRequest(helloVerifyRequestBody: helloVerifyRequestBody),
      firstHelloVerifyRequest
    )

    let alteredInitial = try DTLSClientHello(
      random: [UInt8](repeating: 0x5B, count: 32),
      cookie: []
    ).encodeBytes()
    XCTAssertThrowsError(
      try handshake.ingestClientHello(
        header: makeHeader(sequence: 0, body: alteredInitial),
        body: alteredInitial
      )
    )

    guard case .duplicateVerifiedClientHello = try handshake.ingestClientHello(
      header: verifiedHeader,
      body: verified
    ) else {
      return XCTFail("The accepted ClientHello must request the retained server flight")
    }

    let altered = try makeClientHello(cookie: [0xA1, 0xB3])
    XCTAssertThrowsError(
      try handshake.ingestClientHello(
        header: makeHeader(sequence: 1, body: altered),
        body: altered
      )
    ) { error in
      guard case DTLSError.outOfOrderMessage = error else {
        return XCTFail("A changed ClientHello must fail closed, received: \(error)")
      }
    }
  }

  func testServerEngineRetransmitsTheCorrectRetainedFlight() throws {
    var server = try DTLSServerEngine(configuration: makeEngineConfiguration())
    _ = try server.startHandshake()
    let remoteAddress: [UInt8] = [127, 0, 0, 1, 0xC0, 0x01]

    let initialBody = try makeClientHello(cookie: [])
    let initialMessage = try DTLSHandshakeHeader.encodeMessage(
      type: .clientHello,
      messageSeq: 0,
      body: initialBody
    )
    let firstHVR = try server.receive(
      makeRecord(sequence: 0, handshakeMessage: initialMessage).span,
      from: remoteAddress.span
    )
    XCTAssertFalse(firstHVR.datagramsToSend.isEmpty)

    let verifiedBody = try makeClientHello(cookie: [0xA1, 0xB2])
    let verifiedMessage = try DTLSHandshakeHeader.encodeMessage(
      type: .clientHello,
      messageSeq: 1,
      body: verifiedBody
    )
    let firstServerFlight = try server.receive(
      makeRecord(sequence: 1, handshakeMessage: verifiedMessage).span,
      from: remoteAddress.span
    )
    XCTAssertFalse(firstServerFlight.datagramsToSend.isEmpty)

    let repeatedHVR = try server.receive(
      makeRecord(sequence: 2, handshakeMessage: initialMessage).span,
      from: remoteAddress.span
    )
    XCTAssertEqual(
      try plaintextRecords(in: repeatedHVR.datagramsToSend),
      try plaintextRecords(in: firstHVR.datagramsToSend)
    )

    let repeatedServerFlight = try server.receive(
      makeRecord(sequence: 3, handshakeMessage: verifiedMessage).span,
      from: remoteAddress.span
    )
    XCTAssertEqual(
      try plaintextRecords(in: repeatedServerFlight.datagramsToSend),
      try plaintextRecords(in: firstServerFlight.datagramsToSend)
    )
  }

  private func makeHandshake() -> DTLSServerHandshake {
    DTLSServerHandshake(
      prfContext: makePRFContext(),
      transcriptContext: makeTranscriptContext()
    )
  }

  private func makeEngineConfiguration() -> DTLSEngineConfiguration {
    var configuration = DTLSEngineConfiguration(
      requireClientCertificate: false,
      certificateChainDER: [[0x30, 0x00]],
      signingScheme: .ecdsa_secp256r1_sha256,
      randomBytes: { count in [UInt8](repeating: 0x42, count: count) },
      ecdheGenerate: { _ in
        (
          publicKey: [0x04] + [UInt8](repeating: 0x11, count: 64),
          privateHandle: [UInt8](repeating: 0x22, count: 32)
        )
      },
      ecdheAgree: { _, _, _ in [UInt8](repeating: 0x33, count: 32) },
      sign: { _ in [0x30, 0x00] },
      verifyPeerSignature: { _, _, _ in true },
      makeCookie: { _ in [0xA1, 0xB2] },
      verifyCookie: { cookie, _ in cookie == [0xA1, 0xB2] }
    )
    configuration.prfContext = makePRFContext()
    configuration.transcriptContext = makeTranscriptContext()
    configuration.recordProtectorFactory = { _, _, _ in
      DTLSRecordProtectionContext(
        recordOverhead: 1,
        seal: { _, _, _, _ in },
        open: { _, _, _ in }
      )
    }
    return configuration
  }

  private func makePRFContext() -> DTLSPRFContext {
    DTLSPRFContext(
      hmacSHA256: { first, second, _ in
        [UInt8](repeating: UInt8((first.count + (second?.count ?? 0)) & 0xFF), count: 32)
      },
      hmacSHA384: { first, second, _ in
        [UInt8](repeating: UInt8((first.count + (second?.count ?? 0)) & 0xFF), count: 48)
      }
    )
  }

  private func makeTranscriptContext() -> DTLSTranscriptContext {
    DTLSTranscriptContext(
      sha256: { message in [UInt8](repeating: UInt8(message.count & 0xFF), count: 32) },
      sha384: { message in [UInt8](repeating: UInt8(message.count & 0xFF), count: 48) }
    )
  }

  private func makeClientHello(cookie: [UInt8]) throws -> [UInt8] {
    try DTLSClientHello(
      random: [UInt8](repeating: 0x5A, count: 32),
      cookie: cookie
    ).encodeBytes()
  }

  private func makeHeader(sequence: UInt16, body: [UInt8]) -> DTLSHandshakeHeader {
    DTLSHandshakeHeader(
      messageType: .clientHello,
      length: UInt32(body.count),
      messageSeq: sequence
    )
  }

  private func makeServerFlightInputs() -> DTLSServerHandshake.ServerFlightInputs {
    DTLSServerHandshake.ServerFlightInputs(
      serverRandom: [UInt8](repeating: 0x42, count: 32),
      certificateBody: [0x00, 0x00, 0x00],
      serverKeyExchangeBody: [0x03, 0x00, 0x17, 0x00]
    )
  }

  private func makeRecord(sequence: UInt64, handshakeMessage: [UInt8]) -> [UInt8] {
    precondition(sequence < (1 << 48))
    precondition(handshakeMessage.count <= Int(UInt16.max))
    return [
      DTLSContentType.handshake.rawValue,
      0xFE, 0xFD,
      0x00, 0x00,
      UInt8((sequence >> 40) & 0xFF),
      UInt8((sequence >> 32) & 0xFF),
      UInt8((sequence >> 24) & 0xFF),
      UInt8((sequence >> 16) & 0xFF),
      UInt8((sequence >> 8) & 0xFF),
      UInt8(sequence & 0xFF),
      UInt8((handshakeMessage.count >> 8) & 0xFF),
      UInt8(handshakeMessage.count & 0xFF),
    ] + handshakeMessage
  }

  private func plaintextRecords(in datagrams: [[UInt8]]) throws -> [[UInt8]] {
    var records: [[UInt8]] = []
    for datagram in datagrams {
      var offset = 0
      while offset < datagram.count {
        guard datagram.count - offset >= 13 else { throw TestError.malformedRecord }
        let length = (Int(datagram[offset + 11]) << 8) | Int(datagram[offset + 12])
        let end = offset + 13 + length
        guard end <= datagram.count else { throw TestError.malformedRecord }
        records.append(Array(datagram[(offset + 13)..<end]))
        offset = end
      }
    }
    return records
  }

  private enum TestError: Error {
    case malformedRecord
  }
}
