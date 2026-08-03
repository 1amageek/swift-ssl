import SSLCore
import SSLCrypto
import SSLTLS
import SSLX509
import Synchronization
import XCTest

final class TLS13HandshakeMessageTests: XCTestCase {
  func testDTLSSRTPUseSRTPExtensionRoundTripsInDTLSOnly() throws {
    let identifier = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let offer = DTLSSRTPUseSRTPData(
      protectionProfiles: [.aeadAES128GCM, .aeadAES256GCM],
      masterKeyIdentifier: OwnedBytes(copying: identifier.span)
    )
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
      useSRTP: offer,
      encoding: .dtls13
    )
    let parsedClient = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span,
      encoding: .dtls13
    )
    XCTAssertEqual(parsedClient.useSRTP, offer)

    let selection = DTLSSRTPUseSRTPData(
      protectionProfiles: [.aeadAES256GCM],
      masterKeyIdentifier: OwnedBytes(copying: identifier.span)
    )
    let encryptedExtensions = try TLS13HandshakeCodec.makeEncryptedExtensions(
      useSRTP: selection,
      encoding: .dtls13
    )
    let parsedServer = try TLS13HandshakeCodec.parseEncryptedExtensions(
      encryptedExtensions.span,
      encoding: .dtls13
    )
    XCTAssertEqual(parsedServer.useSRTP, selection)

    XCTAssertThrowsError(
      try TLS13HandshakeCodec.makeClientHello(
        random: ContiguousArray(repeating: 0x11, count: 32).span,
        keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
        useSRTP: offer
      )
    )
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.parseEncryptedExtensions(
        encryptedExtensions.span
      )
    )
  }

  func testClientHelloRoundTrip() throws {
    let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
    let keyShare = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
    let message = try TLS13HandshakeCodec.makeClientHello(
      random: random.span,
      keyShare: keyShare.span
    )
    let parsed = try TLS13HandshakeCodec.parseClientHello(message.span)

    XCTAssertEqual(parsed.namedGroup, .x25519)
    XCTAssertEqual(
      parsed.signatureSchemes,
      [.ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519]
    )
    XCTAssertEqual(copy(parsed.random.span), Array(random))
    XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
  }

  func testRawPublicKeyCertificateTypeExtensionsRoundTrip() throws {
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: UInt8(0x11), count: 32).span,
      keyShare: ContiguousArray(repeating: UInt8(0x22), count: 32).span,
      clientCertificateTypes: [.rawPublicKey, .x509],
      serverCertificateTypes: [.rawPublicKey]
    )
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span
    )
    XCTAssertEqual(
      parsedClientHello.clientCertificateTypes,
      [.rawPublicKey, .x509]
    )
    XCTAssertEqual(
      parsedClientHello.serverCertificateTypes,
      [.rawPublicKey]
    )

    let encryptedExtensions = try TLS13HandshakeCodec.makeEncryptedExtensions(
      clientCertificateType: .rawPublicKey,
      serverCertificateType: .rawPublicKey
    )
    let parsedEncryptedExtensions = try TLS13HandshakeCodec
      .parseEncryptedExtensions(encryptedExtensions.span)
    XCTAssertEqual(
      parsedEncryptedExtensions.clientCertificateType,
      .rawPublicKey
    )
    XCTAssertEqual(
      parsedEncryptedExtensions.serverCertificateType,
      .rawPublicKey
    )
  }

  func testRawPublicKeyCertificateMessageEnforcesSingleSPKI() throws {
    let rawPublicKey = deterministicRawPublicKey()
    let entry = try TLS13CertificateEntry(
      certificateDER: rawPublicKey.span
    )
    let encoded = try TLS13HandshakeCodec.makeCertificate(entries: [entry])
    let parsed = try TLS13HandshakeCodec.parseCertificateMessage(
      encoded.span,
      certificateType: .rawPublicKey
    )
    XCTAssertEqual(parsed.certificateType, .rawPublicKey)
    XCTAssertEqual(parsed.entries.count, 1)
    let parsedEntry = parsed.entries[0]
    let parsedCertificate = parsedEntry.certificate
    XCTAssertEqual(
      copy(parsedCertificate.span),
      Array(rawPublicKey)
    )

    let empty = try TLS13HandshakeCodec.makeCertificate(entries: [])
    let parsedEmpty = try TLS13HandshakeCodec.parseCertificateMessage(
      empty.span,
      certificateType: .rawPublicKey
    )
    XCTAssertTrue(parsedEmpty.entries.isEmpty)

    let chain = try TLS13HandshakeCodec.makeCertificate(
      entries: [entry, entry]
    )
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.parseCertificateMessage(
        chain.span,
        certificateType: .rawPublicKey
      )
    )

    let evidence = ContiguousArray<UInt8>([0x01])
    let entryWithEvidence = try TLS13CertificateEntry(
      certificateDER: rawPublicKey.span,
      stapledOCSPResponse: evidence.span
    )
    let encodedEvidence = try TLS13HandshakeCodec.makeCertificate(
      entries: [entryWithEvidence]
    )
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.parseCertificateMessage(
        encodedEvidence.span,
        certificateType: .rawPublicKey
      )
    )
  }

  func testClientHelloRejectsMissingSignatureAlgorithms() throws {
    let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
    let keyShare = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
    let message = try TLS13HandshakeCodec.makeClientHello(
      random: random.span,
      keyShare: keyShare.span
    )
    var encoded = ContiguousArray(copy(message.span))
    let range = try extensionValueRange(
      type: 0x000D,
      in: encoded,
      clientHello: true
    )
    let listByteCount =
      (Int(encoded[range.lowerBound]) << 8)
      | Int(encoded[range.lowerBound + 1])
    XCTAssertEqual(listByteCount, range.count - 2)
    var offset = range.lowerBound + 2
    while offset < range.upperBound {
      encoded[offset] = 0x7A
      encoded[offset + 1] = 0x7A
      offset += 2
    }

    do {
      _ = try TLS13HandshakeCodec.parseClientHello(encoded.span)
      XCTFail("ClientHello accepted no supported authentication scheme")
    } catch {
      XCTAssertEqual(error, .signatureFailure)
    }
  }

  func testServerHelloRoundTrip() throws {
    let random = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
    let keyShare = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
    let message = try TLS13HandshakeCodec.makeServerHello(
      random: random.span,
      keyShare: keyShare.span
    )
    let parsed = try TLS13HandshakeCodec.parseServerHello(message.span)

    XCTAssertEqual(parsed.cipherSuite, .aes128GCM_SHA256)
    XCTAssertEqual(parsed.namedGroup, .x25519)
    XCTAssertEqual(copy(parsed.random.span), Array(random))
    XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
  }

  func testALPNAndQUICTransportParametersRoundTrip() throws {
    let h3 = try TLS13ApplicationProtocol(
      identifier: ContiguousArray<UInt8>("h3".utf8).span
    )
    let fallback = try TLS13ApplicationProtocol(
      identifier: ContiguousArray<UInt8>("hq-interop".utf8).span
    )
    let clientParameters = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span,
      keyShare: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span,
      applicationProtocols: [h3, fallback],
      transportParameters: clientParameters.span
    )
    let parsedClient = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span
    )
    XCTAssertEqual(parsedClient.applicationProtocols, [h3, fallback])
    let parsedClientParameters = try XCTUnwrap(
      parsedClient.transportParameters
    )
    XCTAssertEqual(copy(parsedClientParameters.span), Array(clientParameters))

    let serverParameters = ContiguousArray<UInt8>([0x04, 0x05])
    let encryptedExtensions = try TLS13HandshakeCodec.makeEncryptedExtensions(
      applicationProtocol: h3,
      transportParameters: serverParameters.span
    )
    let parsedServer = try TLS13HandshakeCodec.parseEncryptedExtensions(
      encryptedExtensions.span
    )
    XCTAssertEqual(parsedServer.applicationProtocol, h3)
    let parsedServerParameters = try XCTUnwrap(
      parsedServer.peerTransportParameters
    )
    XCTAssertEqual(copy(parsedServerParameters.span), Array(serverParameters))
  }

  func testHybridKeyShareUsesRoleSpecificWireEncoding() throws {
    let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
    let clientShare = ContiguousArray<UInt8>(repeating: 0x22, count: 1_216)
    let clientMessage = try TLS13HandshakeCodec.makeClientHello(
      random: random.span,
      namedGroup: .x25519MLKEM768,
      keyShare: clientShare.span
    )
    let parsedClient = try TLS13HandshakeCodec.parseClientHello(clientMessage.span)
    XCTAssertEqual(parsedClient.namedGroup, .x25519MLKEM768)
    XCTAssertEqual(copy(parsedClient.keyShare.span), Array(clientShare))

    let encodedClient = ContiguousArray(copy(clientMessage.span))
    let supportedGroups = try extensionValue(
      type: 0x000A,
      in: encodedClient,
      clientHello: true
    )
    XCTAssertEqual(readUInt16(supportedGroups, at: 0), 2)
    XCTAssertEqual(readUInt16(supportedGroups, at: 2), 0x11EC)
    let clientKeyShare = try extensionValue(
      type: 0x0033,
      in: encodedClient,
      clientHello: true
    )
    XCTAssertEqual(readUInt16(clientKeyShare, at: 0), 1_220)
    XCTAssertEqual(readUInt16(clientKeyShare, at: 2), 0x11EC)
    XCTAssertEqual(readUInt16(clientKeyShare, at: 4), 1_216)
    XCTAssertEqual(clientKeyShare.count, 1_222)

    let serverShare = ContiguousArray<UInt8>(repeating: 0x44, count: 1_120)
    let serverMessage = try TLS13HandshakeCodec.makeServerHello(
      random: random.span,
      namedGroup: .x25519MLKEM768,
      keyShare: serverShare.span
    )
    let parsedServer = try TLS13HandshakeCodec.parseServerHello(serverMessage.span)
    XCTAssertEqual(parsedServer.namedGroup, .x25519MLKEM768)
    XCTAssertEqual(copy(parsedServer.keyShare.span), Array(serverShare))

    let serverKeyShare = try extensionValue(
      type: 0x0033,
      in: ContiguousArray(copy(serverMessage.span)),
      clientHello: false
    )
    XCTAssertEqual(readUInt16(serverKeyShare, at: 0), 0x11EC)
    XCTAssertEqual(readUInt16(serverKeyShare, at: 2), 1_120)
    XCTAssertEqual(serverKeyShare.count, 1_124)
  }

  func testClientKeyShareRejectsInvalidVectorAndGroupMismatch() throws {
    let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
    let clientShare = ContiguousArray<UInt8>(repeating: 0x22, count: 1_216)
    let message = try TLS13HandshakeCodec.makeClientHello(
      random: random.span,
      namedGroup: .x25519MLKEM768,
      keyShare: clientShare.span
    )

    var invalidVector = ContiguousArray(copy(message.span))
    let keyShareRange = try extensionValueRange(
      type: 0x0033,
      in: invalidVector,
      clientHello: true
    )
    invalidVector[keyShareRange.lowerBound + 1] &-= 1
    do {
      _ = try TLS13HandshakeCodec.parseClientHello(invalidVector.span)
      XCTFail("ClientHello accepted an invalid key_share vector length")
    } catch {
      XCTAssertEqual(error, .invalidKeyShare)
    }

    var groupMismatch = ContiguousArray(copy(message.span))
    let groupsRange = try extensionValueRange(
      type: 0x000A,
      in: groupMismatch,
      clientHello: true
    )
    groupMismatch[groupsRange.lowerBound + 2] = 0x00
    groupMismatch[groupsRange.lowerBound + 3] = 0x1D
    do {
      _ = try TLS13HandshakeCodec.parseClientHello(groupMismatch.span)
      XCTFail("ClientHello accepted a key share absent from supported_groups")
    } catch {
      XCTAssertEqual(error, .invalidKeyShare)
    }
  }

  func testCertificateAndFinishedMessagesHaveStrictLengths() throws {
    let certificate = ContiguousArray<UInt8>([1, 2, 3, 4])
    let certificateMessage = try TLS13HandshakeCodec.makeCertificate(
      certificateDER: certificate.span)
    let parsedCertificate = try TLS13HandshakeCodec.parseCertificateMessage(
      certificateMessage.span
    )
    XCTAssertTrue(parsedCertificate.requestContext.isEmpty)
    XCTAssertEqual(parsedCertificate.entries.count, 1)
    let parsedEntry = parsedCertificate.entries[0]
    XCTAssertEqual(
      copy(parsedEntry.certificate.span),
      Array(certificate)
    )

    let verifyData = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
    let finished = try TLS13HandshakeCodec.makeFinished(verifyData: verifyData.span)
    let parsedFinished = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 32)
    XCTAssertEqual(copy(parsedFinished.span), Array(verifyData))

    do {
      _ = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 48)
      XCTFail("finished message with the wrong hash length was accepted")
    } catch {
      XCTAssertEqual(error, .invalidFinished)
    }
  }

  func testCertificateRequestAndEmptyCertificateRoundTrip() throws {
    let context = ContiguousArray<UInt8>([0xA5, 0x5A])
    let request = try TLS13HandshakeCodec.makeCertificateRequest(
      requestContext: context.span,
      signatureSchemes: [.ed25519]
    )
    let parsedRequest = try TLS13HandshakeCodec.parseCertificateRequest(
      request.span
    )
    XCTAssertEqual(copy(parsedRequest.requestContext.span), Array(context))
    XCTAssertEqual(parsedRequest.signatureSchemes, [.ed25519])

    let emptyCertificate = try TLS13HandshakeCodec.makeCertificate(
      entries: [],
      requestContext: context.span
    )
    let parsedCertificate = try TLS13HandshakeCodec.parseCertificateMessage(
      emptyCertificate.span
    )
    XCTAssertEqual(
      copy(parsedCertificate.requestContext.span),
      Array(context)
    )
    XCTAssertTrue(parsedCertificate.entries.isEmpty)
  }

  func testCertificateRequestRejectsMissingSignatureAlgorithms() throws {
    let request = try TLS13HandshakeCodec.makeCertificateRequest()
    var encoded = ContiguousArray(copy(request.span))
    encoded[7] = 0x7A
    encoded[8] = 0x7A

    do {
      _ = try TLS13HandshakeCodec.parseCertificateRequest(encoded.span)
      XCTFail("CertificateRequest accepted no signature_algorithms extension")
    } catch {
      XCTAssertEqual(error, .signatureFailure)
    }
  }

  func testCertificateChainAndStapledEvidenceRoundTrip() throws {
    let ocspResponse = ContiguousArray<UInt8>([0x30, 0x00])
    let sctList = syntacticallyValidSCTList()
    let leaf = try TLS13CertificateEntry(
      certificateDER: ContiguousArray<UInt8>([1, 2, 3]).span,
      stapledOCSPResponse: ocspResponse.span,
      signedCertificateTimestampList: sctList.span
    )
    let issuer = try TLS13CertificateEntry(
      certificateDER: ContiguousArray<UInt8>([4, 5]).span
    )
    let context = ContiguousArray<UInt8>([0xA5])

    let encoded = try TLS13HandshakeCodec.makeCertificate(
      entries: [leaf, issuer],
      requestContext: context.span
    )
    let parsed = try TLS13HandshakeCodec.parseCertificateMessage(encoded.span)

    XCTAssertEqual(copy(parsed.requestContext.span), Array(context))
    XCTAssertEqual(parsed.entries.count, 2)
    let parsedLeaf = parsed.entries[0]
    let parsedIssuer = parsed.entries[1]
    let parsedOCSP = try XCTUnwrap(parsedLeaf.stapledOCSPResponse)
    let parsedSCTs = try XCTUnwrap(parsedLeaf.signedCertificateTimestampList)
    XCTAssertEqual(copy(parsedLeaf.certificate.span), [1, 2, 3])
    XCTAssertEqual(copy(parsedOCSP.span), [0x30, 0])
    XCTAssertEqual(
      copy(parsedSCTs.span),
      Array(sctList)
    )
    XCTAssertEqual(copy(parsedIssuer.certificate.span), [4, 5])
    XCTAssertNil(parsedIssuer.stapledOCSPResponse)
  }

  func testCertificateVerifyCodecCarriesExplicitSignatureScheme() throws {
    let signature = ContiguousArray<UInt8>(repeating: 0x5A, count: 64)
    let message = try TLS13HandshakeCodec.makeCertificateVerify(
      signatureScheme: .ed25519,
      signature: signature.span
    )
    let parsed = try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message.span)
    XCTAssertEqual(parsed.signatureScheme, .ed25519)
    XCTAssertEqual(copy(parsed.signature.span), Array(signature))
    let parsedSignature = try TLS13HandshakeCodec.parseCertificateVerify(message.span)
    XCTAssertEqual(copy(parsedSignature.span), Array(signature))

    var unsupported = ContiguousArray(copy(message.span))
    unsupported[4] = 0x7A
    unsupported[5] = 0x7A
    do {
      _ = try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(unsupported.span)
      XCTFail("the modern profile accepted an unsupported signature scheme")
    } catch {
      XCTAssertEqual(error, .malformedMessage)
    }
  }

  private func syntacticallyValidSCTList() -> ContiguousArray<UInt8> {
    var sct = ContiguousArray<UInt8>([0])
    sct.append(contentsOf: repeatElement(0x11, count: 32))
    sct.append(contentsOf: repeatElement(0, count: 8))
    sct.append(contentsOf: [0, 0, 4, 3, 0, 1, 0x01])
    var list = ContiguousArray<UInt8>([0, UInt8(sct.count + 2), 0, UInt8(sct.count)])
    list.append(contentsOf: sct)
    return list
  }

  func testKeyUpdateCodecRejectsInvalidRequestValue() throws {
    let message = try TLS13HandshakeCodec.makeKeyUpdate(requestUpdate: true)
    XCTAssertTrue(try TLS13HandshakeCodec.parseKeyUpdate(message.span))

    var malformed = ContiguousArray(copy(message.span))
    malformed[malformed.count - 1] = 2
    do {
      _ = try TLS13HandshakeCodec.parseKeyUpdate(malformed.span)
      XCTFail("invalid KeyUpdate request value was accepted")
    } catch {
      XCTAssertEqual(error, .malformedMessage)
    }
  }

  func testResumptionStateDerivesSingleUsePSKAndObfuscatedAge() throws {
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 500_000_000
    )
    let ticket = ContiguousArray<UInt8>(repeating: 0xA5, count: 24)
    let nonce = ContiguousArray<UInt8>([2, 3, 4])
    let masterSecret = ContiguousArray<UInt8>(0..<32)
    var state = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: masterSecret.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 0x0102_0304
    )

    let nextInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 500_000_000
    )
    XCTAssertEqual(
      try state.obfuscatedTicketAge(at: nextInstant),
      1_000 &+ 0x0102_0304
    )
    state.withTicketBytes { bytes in
      XCTAssertEqual(copy(bytes), Array(ticket))
    }

    let psk = try state.consumePSK()
    psk.withBorrowedBytes { pskBytes in
      XCTAssertEqual(
        copy(pskBytes),
        Array(bytes("3a1b984196e77cb20bf67b6bb7659285b90b447c293fdd7d14e44f06916539c3"))
      )
    }
    XCTAssertTrue(state.isConsumed)
    do {
      _ = try state.consumePSK()
      XCTFail("a resumption PSK was consumed more than once")
    } catch {
      XCTAssertEqual(error, .replayDetected)
    }

    let beforeIssue = try VerificationInstant(
      secondsSinceUnixEpoch: 1_719_999_999,
      nanoseconds: 500_000_000
    )
    do {
      _ = try state.obfuscatedTicketAge(at: beforeIssue)
      XCTFail("a ticket age before issuance was accepted")
    } catch {
      XCTAssertEqual(error, .issuedInFuture)
    }

    let afterExpiry = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_003_601,
      nanoseconds: 500_000_000
    )
    do {
      _ = try state.obfuscatedTicketAge(at: afterExpiry)
      XCTFail("an expired ticket was accepted")
    } catch {
      XCTAssertEqual(error, .expired)
    }
  }

  func testDeterministicClientServerHandshakeCompletes() throws {
    let seed = deterministicSeed()
    let certificate = deterministicCertificate()
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span)
    let serverEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span)
    let signingKey = try Ed25519PrivateKey(seed: seed.span)
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientEphemeral,
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: serverEphemeral,
      certificateDER: certificate.span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let serverFinished = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
    XCTAssertTrue(serverFinished.actions.contains(.handshakeConfirmed))

    let applicationData = ContiguousArray<UInt8>([0x61, 0x70, 0x70, 0x2D, 0x31])
    let applicationOutput = try client.sendApplicationData(applicationData.span)
    let received = try server.receiveApplicationRecord(applicationOutput.bytes.span)
    XCTAssertEqual(copy(received.span), Array(applicationData))

    let response = ContiguousArray<UInt8>([0x6F, 0x6B])
    let responseOutput = try server.sendApplicationData(response.span)
    let clientReceived = try client.receiveApplicationRecord(responseOutput.bytes.span)
    XCTAssertEqual(copy(clientReceived.span), Array(response))

    let clientKeyUpdate = try client.requestKeyUpdate(requestPeerUpdate: true)
    let serverKeyUpdateResponse = try server.receivePostHandshakeRecord(
      clientKeyUpdate.bytes.span
    )
    XCTAssertFalse(serverKeyUpdateResponse.bytes.isEmpty)
    let clientKeyUpdateConsumed = try client.receivePostHandshakeRecord(
      serverKeyUpdateResponse.bytes.span
    )
    XCTAssertTrue(clientKeyUpdateConsumed.bytes.isEmpty)

    let postUpdateClientData = ContiguousArray<UInt8>([0x6E, 0x65, 0x77])
    let postUpdateClientOutput = try client.sendApplicationData(postUpdateClientData.span)
    let postUpdateClientReceived = try server.receiveApplicationRecord(
      postUpdateClientOutput.bytes.span
    )
    XCTAssertEqual(copy(postUpdateClientReceived.span), Array(postUpdateClientData))

    let postUpdateServerData = ContiguousArray<UInt8>([0x6F, 0x6C, 0x64])
    let postUpdateServerOutput = try server.sendApplicationData(postUpdateServerData.span)
    let postUpdateServerReceived = try client.receiveApplicationRecord(
      postUpdateServerOutput.bytes.span
    )
    XCTAssertEqual(copy(postUpdateServerReceived.span), Array(postUpdateServerData))
  }

  func testStreamExternalServerCredentialCompletesThroughTransitions() throws {
    let certificate = deterministicCertificate()
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      externalServerCredential: TLS13ExternalServerCredential(),
      verificationInstant: instant
    )
    let clientHello = try client.start()
    let selectionTransition = try server.receiveRecordStep(
      clientHello.bytes.span
    )
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selectionTransition {
    case .suspended(.credentialSelection(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      selectionRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("server credential selection did not suspend")
    }
    let credential = try TLS13CredentialDescriptor(
      identifier: ContiguousArray("stream-server-key".utf8).span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificate.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    let signatureTransition = try server.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("server signature did not suspend")
    }
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: signatureRequest.message.span)
    let serverFlightTransition = try server.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let serverFlight: TLS13HandshakeOutput
    switch consume serverFlightTransition {
    case .output(let output):
      serverFlight = output
    case .suspended:
      return XCTFail("verified signature suspended again")
    }
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testStreamRawPublicKeyCompletesThroughExternalCapabilities() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let rawPublicKey = deterministicRawPublicKey()
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      externalServerTrust: TLS13ExternalServerTrust(
        certificateType: .rawPublicKey
      ),
      serverName: ContiguousArray("server.example".utf8).span,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      externalServerCredential: TLS13ExternalServerCredential(
        certificateTypes: [.rawPublicKey]
      ),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    let selectionTransition = try server.receiveRecordStep(
      clientHello.bytes.span
    )
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selectionTransition {
    case .suspended(.credentialSelection(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      selectionRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("server credential selection did not suspend")
    }
    XCTAssertEqual(selectionRequest.certificateTypes, [.rawPublicKey])

    let credential = try TLS13CredentialDescriptor(
      identifier: ContiguousArray("raw-server-key".utf8).span,
      rawPublicKeyDER: rawPublicKey.span,
      signatureScheme: .ed25519
    )
    let signatureTransition = try server.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("server signature did not suspend")
    }
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: signatureRequest.message.span)
    let serverFlightTransition = try server.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let serverFlight: TLS13HandshakeOutput
    switch consume serverFlightTransition {
    case .output(let output):
      serverFlight = output
    case .suspended:
      return XCTFail("verified signature suspended again")
    }

    let recordRanges = try tlsRecordRanges(serverFlight.bytes.span)
    XCTAssertEqual(recordRanges.count, 5)
    for index in 0..<2 {
      let transition = try client.receiveRecordStep(
        try serverFlight.bytes.span(in: recordRanges[index])
      )
      switch consume transition {
      case .output(let output):
        XCTAssertTrue(output.bytes.isEmpty)
      case .suspended:
        return XCTFail("pre-certificate record unexpectedly suspended")
      }
    }

    let trustTransition = try client.receiveRecordStep(
      try serverFlight.bytes.span(in: recordRanges[2])
    )
    let trustRequest: TLS13PeerTrustEvaluationRequest
    switch consume trustTransition {
    case .suspended(.peerTrustEvaluation(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      trustRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("raw public key trust evaluation did not suspend")
    }
    XCTAssertEqual(trustRequest.certificateMessage.certificateType, .rawPublicKey)
    XCTAssertEqual(trustRequest.certificateMessage.entries.count, 1)
    let trustEntry = trustRequest.certificateMessage.entries[0]
    let trustCertificate = trustEntry.certificate
    XCTAssertEqual(
      copy(trustCertificate.span),
      Array(rawPublicKey)
    )

    let trustResume = try client.resume(
      .peerTrustAccepted(trustRequest.token)
    )
    switch consume trustResume {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("accepted raw public key trust suspended again")
    }

    let certificateVerifyTransition = try client.receiveRecordStep(
      try serverFlight.bytes.span(in: recordRanges[3])
    )
    switch consume certificateVerifyTransition {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("CertificateVerify unexpectedly suspended")
    }
    let finishedTransition = try client.receiveRecordStep(
      try serverFlight.bytes.span(in: recordRanges[4])
    )
    let clientFinished: TLS13HandshakeOutput
    switch consume finishedTransition {
    case .output(let output):
      clientFinished = output
    case .suspended:
      return XCTFail("Finished unexpectedly suspended")
    }
    _ = try server.receive(clientFinished.bytes.span)
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testStreamCertificateCompressionCompletesThroughPureSwiftCodec() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificate = deterministicCertificate()
    let clientCodec = TrackingCertificateCompressionCodec()
    let serverCodec = TrackingCertificateCompressionCodec()
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificate.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )
    try client.configureCertificateCompression(
      TLS13CertificateCompressionConfiguration(
        codecs: [clientCodec]
      )
    )
    try server.configureCertificateCompression(
      TLS13CertificateCompressionConfiguration(
        codecs: [serverCodec]
      )
    )

    let clientHello = try client.start()
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.bytes.span.extracting(5..<clientHello.bytes.count)
    )
    XCTAssertEqual(
      parsedClientHello.certificateCompressionAlgorithms,
      [.zlib]
    )
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertEqual(serverCodec.compressionCallCount, 1)
    XCTAssertEqual(clientCodec.decompressionCallCount, 1)
  }

  func testStreamRawPublicKeyClientAuthenticationCompletes() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificate = deterministicCertificate()
    let rawPublicKey = deterministicRawPublicKey()
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      externalClientCredential: TLS13ExternalClientCredential(
        certificateType: .rawPublicKey
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificate.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        externalTrust: TLS13ExternalClientTrust(
          requirement: .required,
          certificateType: .rawPublicKey
        )
      )
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let serverRecordRanges = try tlsRecordRanges(serverFlight.bytes.span)
    var credentialSelectionRequest: TLS13CredentialSelectionRequest?
    for range in serverRecordRanges {
      let transition = try client.receiveRecordStep(
        try serverFlight.bytes.span(in: range)
      )
      switch consume transition {
      case .output(let output):
        XCTAssertTrue(output.bytes.isEmpty)
      case .suspended(.credentialSelection(let request), let output):
        XCTAssertTrue(output.bytes.isEmpty)
        XCTAssertNil(credentialSelectionRequest)
        credentialSelectionRequest = request
      case .suspended:
        return XCTFail("unexpected external capability request")
      }
    }
    let selectionRequest = try XCTUnwrap(credentialSelectionRequest)
    XCTAssertEqual(selectionRequest.role, .client)
    XCTAssertEqual(selectionRequest.certificateTypes, [.rawPublicKey])

    let credential = try TLS13CredentialDescriptor(
      identifier: ContiguousArray("raw-client-key".utf8).span,
      rawPublicKeyDER: rawPublicKey.span,
      signatureScheme: .ed25519
    )
    let signatureTransition = try client.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("client signature did not suspend")
    }
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: signatureRequest.message.span)
    let clientFlightTransition = try client.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let clientFlight: TLS13HandshakeOutput
    switch consume clientFlightTransition {
    case .output(let output):
      clientFlight = output
    case .suspended:
      return XCTFail("verified client signature suspended again")
    }

    let clientRecordRanges = try tlsRecordRanges(clientFlight.bytes.span)
    XCTAssertEqual(clientRecordRanges.count, 3)
    let trustTransition = try server.receiveRecordStep(
      try clientFlight.bytes.span(in: clientRecordRanges[0])
    )
    let trustRequest: TLS13PeerTrustEvaluationRequest
    switch consume trustTransition {
    case .suspended(.peerTrustEvaluation(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      trustRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("client raw public key trust evaluation did not suspend")
    }
    XCTAssertEqual(trustRequest.peer, .client)
    XCTAssertEqual(trustRequest.certificateMessage.certificateType, .rawPublicKey)
    let trustResume = try server.resume(
      .peerTrustAccepted(trustRequest.token)
    )
    switch consume trustResume {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("accepted client raw public key trust suspended again")
    }

    for index in 1..<clientRecordRanges.count {
      let transition = try server.receiveRecordStep(
        try clientFlight.bytes.span(in: clientRecordRanges[index])
      )
      switch consume transition {
      case .output:
        break
      case .suspended:
        return XCTFail("post-trust client flight unexpectedly suspended")
      }
    }
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertEqual(
      server.authenticatedClientIdentity?.certificateMessage.certificateType,
      .rawPublicKey
    )
  }

  func testStreamExternalTrustResumesRemainingRecordMessages() throws {
    let certificate = deterministicCertificate()
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      externalServerTrust: TLS13ExternalServerTrust(),
      serverName: ContiguousArray("server.example".utf8).span,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificate.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )
    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let recordRanges = try tlsRecordRanges(serverFlight.bytes.span)
    XCTAssertEqual(recordRanges.count, 5)
    let serverHelloRecord = try serverFlight.bytes.span(in: recordRanges[0])
    let initialTransition = try client.receiveRecordStep(serverHelloRecord)
    switch consume initialTransition {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("ServerHello unexpectedly suspended")
    }
    let encryptedExtensionsRecord = try serverFlight.bytes.span(
      in: recordRanges[1]
    )
    let encryptedExtensionsTransition = try client.receiveRecordStep(
      encryptedExtensionsRecord
    )
    switch consume encryptedExtensionsTransition {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("EncryptedExtensions unexpectedly suspended")
    }
    let certificateRecord = try serverFlight.bytes.span(in: recordRanges[2])
    let trustTransition = try client.receiveRecordStep(certificateRecord)
    let trustRequest: TLS13PeerTrustEvaluationRequest
    switch consume trustTransition {
    case .suspended(.peerTrustEvaluation(let request), let output):
      XCTAssertTrue(output.bytes.isEmpty)
      trustRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output:
      return XCTFail("server trust evaluation did not suspend")
    }
    let resumed = try client.resume(.peerTrustAccepted(trustRequest.token))
    switch consume resumed {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("accepted trust result suspended again")
    }
    let certificateVerifyRecord = try serverFlight.bytes.span(
      in: recordRanges[3]
    )
    let certificateVerifyTransition = try client.receiveRecordStep(
      certificateVerifyRecord
    )
    switch consume certificateVerifyTransition {
    case .output(let output):
      XCTAssertTrue(output.bytes.isEmpty)
    case .suspended:
      return XCTFail("CertificateVerify unexpectedly suspended")
    }
    let finishedRecord = try serverFlight.bytes.span(in: recordRanges[4])
    let finishedTransition = try client.receiveRecordStep(finishedRecord)
    let clientFinished: TLS13HandshakeOutput
    switch consume finishedTransition {
    case .output(let output):
      clientFinished = output
    case .suspended:
      return XCTFail("Finished unexpectedly suspended")
    }
    _ = try server.receive(clientFinished.bytes.span)
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testStreamHandshakeCompletesWithRequiredClientAuthentication() throws {
    let certificateDER = deterministicCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientIdentity = try TLS13ClientIdentity(
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      clientIdentity: clientIdentity,
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )
    let clientCompression = TrackingCertificateCompressionCodec()
    let serverCompression = TrackingCertificateCompressionCodec()
    try client.configureCertificateCompression(
      TLS13CertificateCompressionConfiguration(
        codecs: [clientCompression]
      )
    )
    try server.configureCertificateCompression(
      TLS13CertificateCompressionConfiguration(
        codecs: [serverCompression]
      )
    )
    XCTAssertNil(server.authenticatedClientIdentity)

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinalFlight = try client.receive(serverFlight.bytes.span)
    XCTAssertNil(server.authenticatedClientIdentity)
    let confirmation = try server.receive(clientFinalFlight.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertNotNil(server.authenticatedClientIdentity)
    XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
    XCTAssertEqual(serverCompression.compressionCallCount, 1)
    XCTAssertEqual(clientCompression.decompressionCallCount, 1)
    XCTAssertEqual(clientCompression.compressionCallCount, 1)
    XCTAssertEqual(serverCompression.decompressionCallCount, 1)
  }

  func testStreamPostHandshakeClientAuthenticationUsesApplicationRecords()
    throws
  {
    let certificateDER = deterministicCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientIdentity = try TLS13ClientIdentity(
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      clientIdentity: clientIdentity,
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        timing: .postHandshake,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )

    let clientHello = try client.start()
    let clientHelloMessage = clientHello.bytes.span.extracting(
      5..<clientHello.bytes.count
    )
    XCTAssertTrue(
      try TLS13HandshakeCodec.parseClientHello(clientHelloMessage)
        .offersPostHandshakeAuthentication
    )
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)
    XCTAssertNil(server.authenticatedClientIdentity)

    let context: ContiguousArray<UInt8> = [0x10, 0x20, 0x30, 0x40]
    let request = try server.requestPostHandshakeClientAuthentication(
      requestContext: context.span
    )
    XCTAssertEqual(try tlsRecordRanges(request.bytes.span).count, 1)
    let response = try client.receivePostHandshakeRecord(request.bytes.span)
    let responseRecords = try tlsRecordRanges(response.bytes.span)
    XCTAssertEqual(responseRecords.count, 3)
    for range in responseRecords {
      let result = try server.receivePostHandshakeRecord(
        try response.bytes.span(in: range)
      )
      XCTAssertTrue(result.bytes.isEmpty)
    }
    XCTAssertNotNil(server.authenticatedClientIdentity)
  }

  func testHybridStreamHandshakeCompletes() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientKeyExchange = try TLS13X25519MLKEM768ClientKeyExchange.generate(
      mlkemEntropy: FixedEntropy(bytes: sequential(count: 64, seed: 0x10)),
      x25519Entropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x30))
    )
    let serverKeyExchange = try TLS13X25519MLKEM768ServerKeyExchange.generate(
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
    )
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let certificateDER = deterministicCertificate()
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      keyExchange: clientKeyExchange,
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      keyExchange: serverKeyExchange,
      keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let confirmation = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
    XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
  }

  func testP256StreamHandshakeCompletes() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      keyExchange: TLS13P256ClientKeyExchange(
        privateKey: try P256PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      keyExchange: TLS13P256ServerKeyExchange(
        privateKey: try P256PrivateKey(
          bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.bytes.span.extracting(5..<clientHello.bytes.count)
    )
    XCTAssertEqual(parsedClientHello.namedGroup, .secp256r1)
    XCTAssertEqual(parsedClientHello.keyShare.count, 65)
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let confirmation = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
    XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
  }

  func testP256ECDSAServerAuthenticationCompletes() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_750_000_000,
      nanoseconds: 0
    )
    let certificateDER = makeECDSACertificate()
    var privateScalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    privateScalar[31] = 1
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x41, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x51, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x42, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x52, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        p256: try P256PrivateKey(bytes: privateScalar.span)
      ),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let confirmation = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
    XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
  }

  func testRSAPSSServerAuthenticationCompletes() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_785_715_200,
      nanoseconds: 0
    )
    let certificateDER = rsaCertificate()
    let privateKey = try RSAPrivateKey(
      modulus: rsaModulus().span,
      publicExponent: 65_537,
      privateExponent: rsaPrivateExponent().span
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x61, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x71, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x62, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x72, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(rsaPSS: privateKey),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let confirmation = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
    XCTAssertTrue(confirmation.actions.contains(.handshakeConfirmed))
  }

  func testDeterministicHandshakeSupportsAllTLS13CipherSuites() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    for cipherSuite in TLSCipherSuite.allCases {
      let clientEphemeral = try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      )
      let serverEphemeral = try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      )
      let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
      let certificateDER = deterministicCertificate()
      var client = try TLS13ClientHandshake(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: clientEphemeral,
        certificateValidator: try makeCertificateValidator(
          certificateDER: certificateDER
        ),
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite
      )
      var server = try TLS13ServerHandshake(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: serverEphemeral,
        certificateDER: certificateDER.span,
        signingKey: TLS13SigningKey(ed25519: signingKey),
        verificationInstant: verificationInstant
      )

      let clientHello = try client.start()
      let serverFlight = try server.receive(clientHello.bytes.span)
      let clientFinished = try client.receive(serverFlight.bytes.span)
      _ = try server.receive(clientFinished.bytes.span)
      XCTAssertTrue(client.isEstablished, "client did not establish (cipherSuite)")
      XCTAssertTrue(server.isEstablished, "server did not establish (cipherSuite)")
    }
  }

  func testDeterministicPSKResumptionHandshakeCompletesWithoutCertificateFlight() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let serverVerificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 0
    )
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let masterSecret = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    var serverState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: masterSecret.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: verificationInstant,
      lifetime: 3_600,
      ageAdd: 7
    )
    let serverPSK = try serverState.consumePSK()
    let clientState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: masterSecret.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: verificationInstant,
      lifetime: 3_600,
      ageAdd: 7
    )

    let clientEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    let serverEphemeralBytes = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientEphemeral,
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: verificationInstant,
      resumptionState: consume clientState
    )
    var server = try serverPSK.withBorrowedBytes { psk in
      let serverEphemeral = try X25519PrivateKey(bytes: serverEphemeralBytes.span)
      return try TLS13ServerHandshake(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: serverEphemeral,
        certificateDER: deterministicCertificate().span,
        signingKey: TLS13SigningKey(
          ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        ),
        verificationInstant: serverVerificationInstant,
        resumptionIdentity: ticket.span,
        resumptionPSK: psk,
        resumptionIssuedAt: verificationInstant,
        resumptionLifetime: 3_600,
        resumptionAgeAdd: 7
      )
    }

    let clientHello = try client.start()
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.bytes.span.extracting(5..<clientHello.bytes.count)
    )
    XCTAssertNotNil(parsedClientHello.preSharedKey)
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    let serverFinished = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertTrue(serverFinished.actions.contains(.handshakeConfirmed))
  }

  func testTLS13EarlyDataAcceptanceAndRejectionAreExplicit() throws {
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let receivedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 0
    )
    let applicationProtocolBytes = ContiguousArray("early-data".utf8)
    let applicationProtocol = try TLS13ApplicationProtocol(
      identifier: applicationProtocolBytes.span
    )
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let masterSecret = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    let payload = ContiguousArray("replayable request".utf8)
    let unknownTicket = ContiguousArray<UInt8>([0xD0, 0xE0, 0xF0])
    let scenarios: [(
      decision: TLS13EarlyDataReplayDecision,
      serverTicket: ContiguousArray<UInt8>,
      acceptsEarlyData: Bool
    )] = [
      (.accept, ticket, true),
      (.reject, ticket, false),
      (.accept, unknownTicket, false),
    ]

    for scenario in scenarios {
      var serverState = try TLS13ResumptionState(
        ticket: scenario.serverTicket.span,
        ticketNonce: nonce.span,
        resumptionMasterSecret: masterSecret.span,
        cipherSuite: .aes128GCM_SHA256,
        issuedAt: issuedAt,
        lifetime: 3_600,
        ageAdd: 7,
        maximumEarlyDataByteCount: 1_024,
        applicationProtocol: applicationProtocol
      )
      let serverPSK = try serverState.consumePSK()
      let clientState = try TLS13ResumptionState(
        ticket: ticket.span,
        ticketNonce: nonce.span,
        resumptionMasterSecret: masterSecret.span,
        cipherSuite: .aes128GCM_SHA256,
        issuedAt: issuedAt,
        lifetime: 3_600,
        ageAdd: 7,
        maximumEarlyDataByteCount: 1_024,
        applicationProtocol: applicationProtocol
      )
      var client = try TLS13ClientHandshake(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        ),
        certificateValidator: try makeCertificateValidator(
          certificateDER: deterministicCertificate()
        ),
        applicationProtocols: [applicationProtocol],
        verificationInstant: issuedAt,
        resumptionState: clientState,
        earlyDataConfiguration: try TLS13EarlyDataClientConfiguration(
          maximumByteCount: 512
        )
      )
      var server = try serverPSK.withBorrowedBytes { psk in
        try TLS13ServerHandshake(
          random: ContiguousArray(repeating: 0x02, count: 32).span,
          ephemeralKey: X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
          ),
          certificateDER: deterministicCertificate().span,
          signingKey: TLS13SigningKey(
            ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
          ),
          verificationInstant: receivedAt,
          applicationProtocolSelector:
            try ServerPreferredTLS13ApplicationProtocolSelector(
              supportedProtocols: [applicationProtocol]
            ),
          resumptionIdentity: scenario.serverTicket.span,
          resumptionPSK: psk,
          resumptionIssuedAt: issuedAt,
          resumptionLifetime: 3_600,
          resumptionAgeAdd: 7,
          resumptionMaximumEarlyDataByteCount: 1_024,
          resumptionApplicationProtocol: applicationProtocol,
          earlyDataConfiguration: try TLS13EarlyDataServerConfiguration(
            maximumByteCount: 512,
            replayProtector: FixedEarlyDataReplayProtector(
              decision: scenario.decision
            )
          )
        )
      }

      let clientHello = try client.start()
      XCTAssertEqual(client.earlyDataState, TLS13EarlyDataState.offered)
      XCTAssertEqual(client.earlyDataByteLimit, 512)
      let earlyRecord = try client.sendEarlyData(payload.span)
      do {
        _ = try client.sendEarlyData(
          ContiguousArray<UInt8>(repeating: 0xA5, count: 512).span
        )
        XCTFail("client exceeded the negotiated early-data byte limit")
      } catch let error {
        XCTAssertEqual(error, .invalidConfiguration)
      }
      var firstFlight = ContiguousArray<UInt8>()
      firstFlight.append(contentsOf: copy(clientHello.bytes.span))
      firstFlight.append(contentsOf: copy(earlyRecord.bytes.span))

      let serverOutput = try server.receive(firstFlight.span)
      let serverFlight = try emittedRecordBytes(serverOutput)
      let delivered = try deliveredEarlyData(serverOutput)
      if scenario.acceptsEarlyData {
        XCTAssertEqual(server.earlyDataState, TLS13EarlyDataState.accepted)
        XCTAssertEqual(delivered, payload)
        XCTAssertTrue(serverOutput.actions.contains(.earlyDataAccepted))
      } else {
        XCTAssertEqual(server.earlyDataState, TLS13EarlyDataState.rejected)
        XCTAssertNil(delivered)
        XCTAssertTrue(serverOutput.actions.contains(.earlyDataRejected))
      }

      let clientFinal = try client.receive(serverFlight.span)
      XCTAssertEqual(
        client.earlyDataState,
        scenario.acceptsEarlyData
          ? TLS13EarlyDataState.accepted
          : TLS13EarlyDataState.rejected
      )
      let serverFinal = try server.receive(clientFinal.bytes.span)
      XCTAssertTrue(client.isEstablished)
      XCTAssertTrue(server.isEstablished)
      XCTAssertTrue(serverFinal.actions.contains(.handshakeConfirmed))
    }
  }

  func testNewSessionTicketIsEncryptedAndProducesResumptionState() throws {
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    let serverEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientEphemeral,
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: verificationInstant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: serverEphemeral,
      certificateDER: deterministicCertificate().span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: verificationInstant
    )
    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)

    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let ticketOutput = try server.sendNewSessionTicket(
      lifetime: 3_600,
      ageAdd: 7,
      ticketNonce: nonce.span,
      ticket: ticket.span,
      issuedAt: verificationInstant
    )
    let ticketRecord = ticketOutput.output.bytes
    var serverState = ticketOutput.takeResumptionState()
    var state = try client.receiveNewSessionTicket(
      ticketRecord.span,
      receivedAt: verificationInstant
    )
    state.withTicketBytes { bytes in
      XCTAssertEqual(copy(bytes), Array(ticket))
    }
    XCTAssertEqual(try state.obfuscatedTicketAge(at: verificationInstant), 7)
    let serverPSK = try serverState.consumePSK()
    let clientPSK = try state.consumePSK()
    try serverPSK.withBorrowedBytes { serverBytes in
      try clientPSK.withBorrowedBytes { clientBytes in
        XCTAssertTrue(ConstantTime.equal(serverBytes, clientBytes))
      }
    }
  }

  func testClientRejectsTamperedServerFlight() throws {
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let serverEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: serverEphemeral,
      certificateDER: deterministicCertificate().span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: verificationInstant
    )
    let clientEphemeral = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientEphemeral,
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: verificationInstant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    var tampered = ContiguousArray(copy(serverFlight.bytes.span))
    tampered[tampered.count - 1] ^= 0x01

    do {
      _ = try client.receive(tampered.span)
      XCTFail("tampered server flight was accepted")
    } catch let error {
      XCTAssertEqual(error, .record(.authenticationFailed))
    }
  }

  func testServerRejectsCertificateOutsideVerificationWindow() throws {
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let ephemeralKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span
    )
    let verificationInstant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_800_000_000,
      nanoseconds: 0
    )

    do {
      _ = try TLS13ServerHandshake(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: ephemeralKey,
        certificateDER: deterministicCertificate().span,
        signingKey: TLS13SigningKey(ed25519: signingKey),
        verificationInstant: verificationInstant
      )
      XCTFail("certificate outside the verification window was accepted")
    } catch let error {
      XCTAssertEqual(error, .certificateNotValid)
    }
  }

  private func copy(_ span: Span<UInt8>) -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private func emittedRecordBytes(
    _ output: TLS13HandshakeOutput
  ) throws -> OwnedBytes {
    for action in output.actions {
      if case .emitRecordBytes(let range) = action {
        return OwnedBytes(copying: try output.bytes.span(in: range))
      }
    }
    throw TLS13HandshakeEngineError.invalidState
  }

  private func deliveredEarlyData(
    _ output: TLS13HandshakeOutput
  ) throws -> ContiguousArray<UInt8>? {
    for action in output.actions {
      if case .deliverApplicationData(let range, let isEarlyData) = action,
        isEarlyData
      {
        return ContiguousArray(copy(try output.bytes.span(in: range)))
      }
    }
    return nil
  }

  private func tlsRecordRanges(
    _ bytes: Span<UInt8>
  ) throws -> ContiguousArray<ByteRange> {
    var result = ContiguousArray<ByteRange>()
    var offset = 0
    while offset < bytes.count {
      guard offset + 5 <= bytes.count else {
        throw TLS13HandshakeEngineError.malformedInput
      }
      let payloadByteCount =
        (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
      let recordByteCount = 5 + payloadByteCount
      guard offset + recordByteCount <= bytes.count else {
        throw TLS13HandshakeEngineError.malformedInput
      }
      result.append(
        try ByteRange(offset: offset, count: recordByteCount)
      )
      offset += recordByteCount
    }
    return result
  }

  private func extensionValue(
    type: UInt16,
    in message: ContiguousArray<UInt8>,
    clientHello: Bool
  ) throws -> ContiguousArray<UInt8> {
    let range = try extensionValueRange(
      type: type,
      in: message,
      clientHello: clientHello
    )
    return ContiguousArray(message[range])
  }

  private func extensionValueRange(
    type: UInt16,
    in message: ContiguousArray<UInt8>,
    clientHello: Bool
  ) throws -> Range<Int> {
    let extensionsStart = clientHello ? 47 : 44
    guard message.count >= extensionsStart else {
      throw TLS13HandshakeError.malformedMessage
    }
    let extensionsByteCount = Int(readUInt16(message, at: extensionsStart - 2))
    let extensionsEnd = extensionsStart + extensionsByteCount
    guard extensionsEnd == message.count else {
      throw TLS13HandshakeError.malformedMessage
    }
    var offset = extensionsStart
    while offset < extensionsEnd {
      guard offset + 4 <= extensionsEnd else {
        throw TLS13HandshakeError.malformedMessage
      }
      let extensionType = readUInt16(message, at: offset)
      let valueByteCount = Int(readUInt16(message, at: offset + 2))
      let valueStart = offset + 4
      let valueEnd = valueStart + valueByteCount
      guard valueEnd <= extensionsEnd else {
        throw TLS13HandshakeError.malformedMessage
      }
      if extensionType == type {
        return valueStart..<valueEnd
      }
      offset = valueEnd
    }
    throw TLS13HandshakeError.unsupportedExtension(type)
  }

  private func readUInt16(
    _ bytes: ContiguousArray<UInt8>,
    at offset: Int
  ) -> UInt16 {
    (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
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

  private func sequential(count: Int, seed: UInt8) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(count)
    var index = 0
    while index < count {
      result.append(seed &+ UInt8(truncatingIfNeeded: index))
      index += 1
    }
    return result
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }

  private func deterministicSeed() -> ContiguousArray<UInt8> {
    bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  }

  private func deterministicServerPublicKey() -> ContiguousArray<UInt8> {
    bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
  }

  private func deterministicRawPublicKey() -> ContiguousArray<UInt8> {
    var subjectPublicKeyInfo: ContiguousArray<UInt8> = [
      0x30, 0x2A,
      0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
      0x03, 0x21, 0x00,
    ]
    subjectPublicKeyInfo.append(contentsOf: deterministicServerPublicKey())
    return subjectPublicKeyInfo
  }

  private func deterministicCertificate() -> ContiguousArray<UInt8> {
    bytes(
      "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a"
        + "170d3235303130313030303030305a3000302a300506032b6570032100"
        + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        + "300506032b6570034100"
        + "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b"
        + "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
    )
  }

  private func makeECDSACertificate() -> ContiguousArray<UInt8> {
    bytes(
      "3082016930820110a003020102020107300a06082a8648ce3d04030230223120301e"
        + "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d"
        + "3235303130313030303030305a170d3335303130313030303030305a30223120301e"
        + "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013"
        + "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e"
        + "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f"
        + "9e162bce33576b315ececbb6406837bf51f5a3373035300f0603551d130101ff0405"
        + "30030101ff30220603551d11041b3019821773776966742d73736c2d65636473612e"
        + "6578616d706c65300a06082a8648ce3d040302034700304402207d64b4f0d8d41a49"
        + "720e591dc1844556462cd8beb44558fa9f63156a76f2c6cc022063756eb89655ab0b"
        + "0b04032d184382dd99e0be5ce5cacc66374a36dc83f7ac23"
    )
  }

  private func rsaModulus() -> ContiguousArray<UInt8> {
    bytes(
      "daff26f7df96632c4d130150fc81d99f6d1913e98dd62dbe34d772e926602c94"
        + "e30c6839d6d60534b9e13c4ae0717aff5bea4978bc07f9372e1cf1fe59e44af1"
        + "95888d435b511564b3dbdebabf2b0ee7b8f9ef02c5379c7ca237ca32b32c6edc"
        + "1469e8a2943e079225f36820d96655817f14c27d0eb36007f6f7ccfc2c58adec"
        + "61d57cdb1481aca798529cd0bbae9dac029c43cf5c1e83236585670373aa9852f"
        + "226adc2697b266137b965d9954072938d3bb6d6c009dc228737b9cd1988e41835"
        + "82714973f2ba34a7159f24829000dbb6167c3edfd2899e73b7d20b6c3ef347e0"
        + "72fe2cfd458282ffc12ea537a7264f88b63480c3d5218d9ae9118ed2f4a361"
    )
  }

  private func rsaPrivateExponent() -> ContiguousArray<UInt8> {
    bytes(
      "30a2f82996cb948cf3352456b32db78253bd7d11a2c18d792fcd25a52833b5d2"
        + "ff35f333dd45bcf43fd0090eec17e7e42caab4d48e960ac0398a8e281a18bc98"
        + "38c891ef02a9d8617c1c79b3e9df0b396578849f8de352eacf302ac4e5cc1976"
        + "e145c037d34a8f6de2e5d31b708cecb28ce1b46c07c6c8ae1c285eab26c22f2"
        + "5e61fb39a663feae56fc905311ae0597dd985ceafa8e46cf811900b8b8a61547"
        + "bc4fa799098dcf9fa34dc3e71262496becf4438a3e3444f5eca8ee5102fe3ec3"
        + "c6839919f02b65b68a0c4140939cfd7d212f2a7a081cb93dc388c50d9f117240"
        + "f2c78e7e197bb31f09ea8d2d831929a954fc1f2d909e2ffca4948fe7565a3521d"
    )
  }

  private func rsaCertificate() -> ContiguousArray<UInt8> {
    bytes(
      "308202b43082019c020101300d06092a864886f70d01010b05003020311e301c06"
        + "035504030c1573776966742d73736c2d7273612e6578616d706c65301e170d3236"
        + "303830323138313331315a170d3336303733303138313331315a3020311e301c06"
        + "035504030c1573776966742d73736c2d7273612e6578616d706c6530820122300d"
        + "06092a864886f70d01010105000382010f003082010a0282010100daff26f7df96"
        + "632c4d130150fc81d99f6d1913e98dd62dbe34d772e926602c94e30c6839d6d6"
        + "0534b9e13c4ae0717aff5bea4978bc07f9372e1cf1fe59e44af195888d435b51"
        + "1564b3dbdebabf2b0ee7b8f9ef02c5379c7ca237ca32b32c6edc1469e8a2943e"
        + "079225f36820d96655817f14c27d0eb36007f6f7ccfc2c58adec61d57cdb1481"
        + "aca798529cd0bbae9dac029c43cf5c1e83236585670373aa9852f226adc2697b2"
        + "66137b965d9954072938d3bb6d6c009dc228737b9cd1988e4183582714973f2ba"
        + "34a7159f24829000dbb6167c3edfd2899e73b7d20b6c3ef347e072fe2cfd4582"
        + "82ffc12ea537a7264f88b63480c3d5218d9ae9118ed2f4a3610203010001300d"
        + "06092a864886f70d01010b05000382010100d600b3f8c5f35a10db8605b1e3dc"
        + "16bf346dea22d6c803d7f4ec90238a7a258f5b23eb8bb0623beb6cc096f5a4de"
        + "93f5e7fddd049342121f814ae6570a3160c72896480d0a6f07aae0f9fa2358fc"
        + "27a8e70250724b944c0be7dfbc57bae2b63d30c3c65f33b8a96e568091971cf3"
        + "9716ae8b2c4c2b6e5efd6c1d623603e0bb1771d5703a3a41ad5412242f027694"
        + "1a382767b1453c281ee00acd9f13c2f5425877d835f1be4b4070d78acfb4eaef"
        + "1c6e46d947ea7e7f3156fd96b2b584fd8b0744721ea69ff9d98c2271d06783c9"
        + "1d51f95437643efd55583bda35b393f510d25c1482b5b49192b622f67d159a83"
        + "5e4e94e54e5d23ae685954ab73a83c41a435"
    )
  }

  private func makeCertificateValidator(
    certificateDER: ContiguousArray<UInt8>
  ) throws -> RFC5280TLS13ServerCertificateValidator {
    try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [try X509Certificate(der: certificateDER.span)]
    )
  }
}

private struct FixedEarlyDataReplayProtector: TLS13EarlyDataReplayProtecting {
  let decision: TLS13EarlyDataReplayDecision

  func evaluate(
    _ context: TLS13EarlyDataReplayContext
  ) throws -> TLS13EarlyDataReplayDecision {
    _ = context
    return decision
  }
}

final class TrackingCertificateCompressionCodec:
  TLS13CertificateCompressionCoding,
  Sendable
{
  private struct State: Sendable {
    var compressionCallCount = 0
    var decompressionCallCount = 0
  }

  let algorithm = TLS13CertificateCompressionAlgorithm.zlib
  private let state = Mutex(State())
  private let base = TLS13ZlibCertificateCompression()

  var compressionCallCount: Int {
    state.withLock { $0.compressionCallCount }
  }

  var decompressionCallCount: Int {
    state.withLock { $0.decompressionCallCount }
  }

  func compress(
    _ certificateMessage: Span<UInt8>
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes {
    state.withLock { $0.compressionCallCount += 1 }
    return try base.compress(certificateMessage)
  }

  func decompress(
    _ compressedCertificateMessage: Span<UInt8>,
    uncompressedByteCount: Int,
    maximumUncompressedByteCount: Int
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes {
    state.withLock { $0.decompressionCallCount += 1 }
    return try base.decompress(
      compressedCertificateMessage,
      uncompressedByteCount: uncompressedByteCount,
      maximumUncompressedByteCount: maximumUncompressedByteCount
    )
  }
}
