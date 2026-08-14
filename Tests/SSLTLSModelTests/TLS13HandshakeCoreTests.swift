import SSLCore
import SSLCrypto
import SSLX509
import XCTest

@testable import SSLTLS

final class TLS13HandshakeCoreTests: XCTestCase {
  func testP256ECDSASignatureCodecRoundTripsAndRejectsNonCanonicalDER() throws {
    var raw = ContiguousArray<UInt8>(repeating: 0, count: 64)
    raw[0] = 0x80
    raw[31] = 0x01
    raw[32] = 0x7F
    raw[63] = 0x02
    let encoded = try TLS13ECDSASignatureCodec.encodeP256(raw.span)
    let decoded = try TLS13ECDSASignatureCodec.decodeP256(encoded.span)
    XCTAssertEqual(Array(decoded), Array(raw))

    let redundantZero: ContiguousArray<UInt8> = [
      0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01,
    ]
    XCTAssertThrowsError(
      try TLS13ECDSASignatureCodec.decodeP256(redundantZero.span)
    )
    let negativeInteger: ContiguousArray<UInt8> = [
      0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01,
    ]
    XCTAssertThrowsError(
      try TLS13ECDSASignatureCodec.decodeP256(negativeInteger.span)
    )
  }

  func testDTLS13ClientServerHandshakeCompletesWithFragmentationCIDAndACK() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_704_153_600,
      nanoseconds: 0
    )
    let certificateDER = try delegatedCredentialCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let certificateSigningKey = TLS13SigningKey(
      ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
    )
    let clientDelegatedKey = try Ed25519PrivateKey(
      seed: ContiguousArray(repeating: 0x43, count: 32).span
    )
    let clientDelegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: try clientDelegatedKey.publicKey()
      ).span,
      certificate: certificate,
      role: .client,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let serverDelegatedKey = try Ed25519PrivateKey(
      seed: ContiguousArray(repeating: 0x42, count: 32).span
    )
    let serverDelegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: try serverDelegatedKey.publicKey()
      ).span,
      certificate: certificate,
      role: .server,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let serverPeer = try DTLS13PeerContext(
      identity: ascii("client-endpoint").span,
      receivedAt: instant
    )
    let cookieProtector = try HMACSHA256DTLS13CookieProtector(
      key: ContiguousArray(repeating: 0xA5, count: 32).span
    )
    let clientConnectionID: ContiguousArray<UInt8> = [0xC1, 0xC2]
    let serverConnectionID: ContiguousArray<UInt8> = [0x51, 0x52, 0x53]
    let applicationProtocol = try TLS13ApplicationProtocol(
      identifier: ascii("dtls-test").span
    )
    let clientIdentity = try TLS13ClientIdentity(
      certificateEntries: [
        try TLS13CertificateEntry(
          certificateDER: certificateDER.span,
          delegatedCredential: clientDelegatedCredential
        )
      ],
      signingKey: TLS13SigningKey(
        ed25519: clientDelegatedKey
      ),
      verificationInstant: instant
    )
    var client = try DTLS13ClientHandshake.make(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x21, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      clientIdentity: clientIdentity,
      applicationProtocols: [applicationProtocol],
      verificationInstant: instant,
      localConnectionID: clientConnectionID.span,
      peerConnectionID: serverConnectionID.span,
      maximumDatagramByteCount: 256
    )
    var server = try DTLS13ServerHandshake.make(
      random: ContiguousArray(repeating: 0x31, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x41, count: 32).span
      ),
      certificateEntries: [
        try TLS13CertificateEntry(
          certificateDER: certificateDER.span,
          delegatedCredential: serverDelegatedCredential
        )
      ],
      signingKey: TLS13SigningKey(
        ed25519: serverDelegatedKey
      ),
      verificationInstant: instant,
      cookieProtector: cookieProtector,
      applicationProtocolSelector:
        try ServerPreferredTLS13ApplicationProtocolSelector(
          supportedProtocols: [applicationProtocol]
        ),
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        timing: .mainAndPostHandshake,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [try X509Certificate(der: certificateDER.span)]
        )
      ),
      localConnectionID: serverConnectionID.span,
      peerConnectionID: clientConnectionID.span,
      maximumDatagramByteCount: 256
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

    let clientInitial = try client.start()
    let clientInitialDatagrams = try emittedDatagrams(clientInitial)
    XCTAssertEqual(clientInitialDatagrams.count, 1)
    let clientInitialDatagram = clientInitialDatagrams[0]
    let retryFlight = try server.receiveDatagram(
      clientInitialDatagram.span,
      from: serverPeer
    )
    let retryDatagrams = try emittedDatagrams(retryFlight)
    XCTAssertEqual(retryDatagrams.count, 1)
    let retryDatagram = retryDatagrams[0]
    let clientRetryOutput = try client.receiveDatagram(retryDatagram.span)
    let clientRetryDatagrams = try emittedDatagrams(clientRetryOutput)
    XCTAssertFalse(clientRetryDatagrams.isEmpty)
    let differentPeer = try DTLS13PeerContext(
      identity: ascii("different-client-endpoint").span,
      receivedAt: instant
    )
    var rejectedDifferentPeer = false
    for datagram in clientRetryDatagrams {
      do {
        _ = try server.receiveDatagram(datagram.span, from: differentPeer)
      } catch let error {
        XCTAssertEqual(error, .cookie(.authenticationFailed))
        rejectedDifferentPeer = true
        break
      }
    }
    XCTAssertTrue(rejectedDifferentPeer)
    var serverDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in clientRetryDatagrams {
      let serverFlight = try server.receiveDatagram(
        datagram.span,
        from: serverPeer
      )
      serverDatagrams.append(contentsOf: try emittedDatagrams(serverFlight))
    }
    XCTAssertGreaterThan(serverDatagrams.count, 2)

    var clientFinalDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in serverDatagrams {
      let output = try client.receiveDatagram(datagram.span)
      clientFinalDatagrams.append(contentsOf: try emittedDatagrams(output))
    }
    XCTAssertTrue(client.isEstablished)
    XCTAssertFalse(client.isHandshakeConfirmed)
    XCTAssertFalse(clientFinalDatagrams.isEmpty)

    var serverAcknowledgmentDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in clientFinalDatagrams {
      let output = try server.receiveDatagram(datagram.span, from: serverPeer)
      serverAcknowledgmentDatagrams.append(
        contentsOf: try emittedDatagrams(output)
      )
    }
    XCTAssertTrue(server.isEstablished)
    XCTAssertNotNil(server.authenticatedClientIdentity)
    XCTAssertFalse(serverAcknowledgmentDatagrams.isEmpty)
    XCTAssertEqual(serverCompression.compressionCallCount, 1)
    XCTAssertEqual(clientCompression.decompressionCallCount, 1)
    XCTAssertEqual(clientCompression.compressionCallCount, 1)
    XCTAssertEqual(serverCompression.decompressionCallCount, 1)

    for datagram in serverAcknowledgmentDatagrams {
      _ = try client.receiveDatagram(datagram.span)
    }
    XCTAssertTrue(client.isHandshakeConfirmed)
    XCTAssertEqual(client.negotiatedApplicationProtocol, applicationProtocol)
    XCTAssertEqual(server.negotiatedApplicationProtocol, applicationProtocol)

    let postHandshakeContext: ContiguousArray<UInt8> = [0xD1, 0xD2, 0xD3]
    let postHandshakeRequest = try server
      .requestPostHandshakeClientAuthentication(
        requestContext: postHandshakeContext.span
      )
    var postHandshakeResponses = ContiguousArray<OwnedBytes>()
    for datagram in try emittedDatagrams(postHandshakeRequest) {
      let output = try client.receiveDatagram(datagram.span)
      postHandshakeResponses.append(
        contentsOf: try emittedDatagrams(output)
      )
    }
    XCTAssertFalse(postHandshakeResponses.isEmpty)
    var postHandshakeAcknowledgments = ContiguousArray<OwnedBytes>()
    for datagram in postHandshakeResponses {
      let output = try server.receiveDatagram(
        datagram.span,
        from: serverPeer
      )
      postHandshakeAcknowledgments.append(
        contentsOf: try emittedDatagrams(output)
      )
    }
    for datagram in postHandshakeAcknowledgments {
      _ = try client.receiveDatagram(datagram.span)
    }
    XCTAssertNotNil(server.authenticatedClientIdentity)

    let clientPayload = ascii("client application datagram")
    let clientApplicationOutput = try client.sendApplicationData(
      clientPayload.span
    )
    let clientApplicationDatagrams = try emittedDatagrams(
      clientApplicationOutput
    )
    XCTAssertEqual(clientApplicationDatagrams.count, 1)
    let clientApplicationDatagram = clientApplicationDatagrams[0]
    let serverDelivery = try server.receiveDatagram(
      clientApplicationDatagram.span,
      from: serverPeer
    )
    XCTAssertEqual(try deliveredApplicationData(serverDelivery), clientPayload)

    let serverPayload = ascii("server application datagram")
    let serverApplicationOutput = try server.sendApplicationData(
      serverPayload.span
    )
    let serverApplicationDatagrams = try emittedDatagrams(
      serverApplicationOutput
    )
    XCTAssertEqual(serverApplicationDatagrams.count, 1)
    let serverApplicationDatagram = serverApplicationDatagrams[0]
    let clientDelivery = try client.receiveDatagram(
      serverApplicationDatagram.span
    )
    XCTAssertEqual(try deliveredApplicationData(clientDelivery), serverPayload)

    let clientKeyUpdate = try client.requestKeyUpdate(
      requestPeerUpdate: true
    )
    XCTAssertThrowsError(
      try client.sendApplicationData(ascii("blocked until key update ACK").span)
    ) { error in
      XCTAssertEqual(error as? DTLS13ConnectionError, .invalidState)
    }
    let clientKeyUpdateDatagrams = try emittedDatagrams(clientKeyUpdate)
    XCTAssertEqual(clientKeyUpdateDatagrams.count, 1)
    let clientKeyUpdateDatagram = clientKeyUpdateDatagrams[0]
    let serverKeyUpdateOutput = try server.receiveDatagram(
      clientKeyUpdateDatagram.span,
      from: serverPeer
    )
    let serverKeyUpdateDatagrams = try emittedDatagrams(serverKeyUpdateOutput)
    XCTAssertEqual(serverKeyUpdateDatagrams.count, 2)

    var clientAcknowledgments = ContiguousArray<OwnedBytes>()
    for datagram in serverKeyUpdateDatagrams {
      let output = try client.receiveDatagram(datagram.span)
      clientAcknowledgments.append(contentsOf: try emittedDatagrams(output))
    }
    XCTAssertEqual(clientAcknowledgments.count, 1)
    let clientAcknowledgment = clientAcknowledgments[0]
    _ = try server.receiveDatagram(
      clientAcknowledgment.span,
      from: serverPeer
    )

    let updatedClientPayload = ascii("client epoch four")
    let updatedClientOutput = try client.sendApplicationData(
      updatedClientPayload.span
    )
    let updatedClientDatagrams = try emittedDatagrams(updatedClientOutput)
    XCTAssertEqual(updatedClientDatagrams.count, 1)
    let updatedClientDatagram = updatedClientDatagrams[0]
    let updatedServerDelivery = try server.receiveDatagram(
      updatedClientDatagram.span,
      from: serverPeer
    )
    XCTAssertEqual(
      try deliveredApplicationData(updatedServerDelivery),
      updatedClientPayload
    )

    let updatedServerPayload = ascii("server epoch four")
    let updatedServerOutput = try server.sendApplicationData(
      updatedServerPayload.span
    )
    let updatedServerDatagrams = try emittedDatagrams(updatedServerOutput)
    XCTAssertEqual(updatedServerDatagrams.count, 1)
    let updatedServerDatagram = updatedServerDatagrams[0]
    let updatedClientDelivery = try client.receiveDatagram(
      updatedServerDatagram.span
    )
    XCTAssertEqual(
      try deliveredApplicationData(updatedClientDelivery),
      updatedServerPayload
    )
  }

  func testDTLS13ExternalServerCredentialCompletesThroughTransitions() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let peer = try DTLS13PeerContext(
      identity: ascii("external-credential-client").span,
      receivedAt: instant
    )
    let cookieProtector = try HMACSHA256DTLS13CookieProtector(
      key: ContiguousArray(repeating: UInt8(0xA5), count: 32).span
    )
    var client = try DTLS13ClientHandshake.make(
      random: ContiguousArray(repeating: UInt8(0x11), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x21), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: instant
    )
    var server = try DTLS13ServerHandshake.make(
      random: ContiguousArray(repeating: UInt8(0x31), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x41), count: 32).span
      ),
      externalServerCredential: TLS13ExternalServerCredential(),
      verificationInstant: instant,
      cookieProtector: cookieProtector
    )
    let clientInitial = try XCTUnwrap(
      try emittedDatagrams(client.start()).first
    )
    let retryTransition = try server.receiveDatagramStep(
      clientInitial.span,
      from: peer
    )
    let retryBatch: DTLSActionBatch
    switch consume retryTransition {
    case .output(let output):
      retryBatch = output
    case .suspended:
      return XCTFail("initial ClientHello unexpectedly suspended")
    }
    let retry = try XCTUnwrap(try emittedDatagrams(retryBatch).first)
    let clientRetry = try XCTUnwrap(
      try emittedDatagrams(client.receiveDatagram(retry.span)).first
    )
    let selectionTransition = try server.receiveDatagramStep(
      clientRetry.span,
      from: peer
    )
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selectionTransition {
    case .suspended(.credentialSelection(let request), _):
      selectionRequest = request
    case .suspended:
      return XCTFail("unexpected capability request")
    case .output:
      return XCTFail("credential selection did not suspend")
    }
    let credential = try TLS13CredentialDescriptor(
      identifier: ascii("dtls-server-key").span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    let signatureTransition = try server.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request), _):
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected capability request")
    case .output:
      return XCTFail("external signature did not suspend")
    }
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signingKey.sign(message: signatureRequest.message.span)
    let serverFlightTransition = try server.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let serverFlight: DTLSActionBatch
    switch consume serverFlightTransition {
    case .output(let output):
      serverFlight = output
    case .suspended:
      return XCTFail("verified signature suspended again")
    }
    var clientFinalDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in try emittedDatagrams(serverFlight) {
      clientFinalDatagrams.append(
        contentsOf: try emittedDatagrams(client.receiveDatagram(datagram.span))
      )
    }
    for datagram in clientFinalDatagrams {
      _ = try server.receiveDatagram(datagram.span, from: peer)
    }
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testDTLS13ExternalServerTrustResumesCoalescedDatagramSuffix() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let peer = try DTLS13PeerContext(
      identity: ascii("external-trust-client").span,
      receivedAt: instant
    )
    let cookieProtector = try HMACSHA256DTLS13CookieProtector(
      key: ContiguousArray(repeating: UInt8(0xB5), count: 32).span
    )
    var client = try DTLS13ClientHandshake.make(
      random: ContiguousArray(repeating: UInt8(0x12), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      externalServerTrust: TLS13ExternalServerTrust(),
      verificationInstant: instant
    )
    var server = try DTLS13ServerHandshake.make(
      random: ContiguousArray(repeating: UInt8(0x32), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x42), count: 32).span
      ),
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      cookieProtector: cookieProtector
    )
    let clientInitial = try XCTUnwrap(
      try emittedDatagrams(client.start()).first
    )
    let retry = try XCTUnwrap(
      try emittedDatagrams(
        server.receiveDatagram(clientInitial.span, from: peer)
      ).first
    )
    let clientRetry = try XCTUnwrap(
      try emittedDatagrams(client.receiveDatagram(retry.span)).first
    )
    let serverDatagrams = try emittedDatagrams(
      server.receiveDatagram(clientRetry.span, from: peer)
    )
    var coalesced = ContiguousArray<UInt8>()
    for datagram in serverDatagrams {
      coalesced.append(contentsOf: copy(datagram.span))
    }
    let trustTransition = try client.receiveDatagramStep(coalesced.span)
    let trustRequest: TLS13PeerTrustEvaluationRequest
    switch consume trustTransition {
    case .suspended(.peerTrustEvaluation(let request), _):
      trustRequest = request
    case .suspended:
      return XCTFail("unexpected capability request")
    case .output:
      return XCTFail("server trust evaluation did not suspend")
    }
    let clientFlightTransition = try client.resume(
      .peerTrustAccepted(trustRequest.token)
    )
    let clientFlight: DTLSActionBatch
    switch consume clientFlightTransition {
    case .output(let output):
      clientFlight = output
    case .suspended:
      return XCTFail("accepted trust result suspended again")
    }
    for datagram in try emittedDatagrams(clientFlight) {
      _ = try server.receiveDatagram(datagram.span, from: peer)
    }
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testP256DTLS13ClientServerHandshakeCompletes() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let serverPeer = try DTLS13PeerContext(
      identity: ascii("p256-client-endpoint").span,
      receivedAt: instant
    )
    let cookieProtector = try HMACSHA256DTLS13CookieProtector(
      key: ContiguousArray(repeating: 0xA5, count: 32).span
    )
    let applicationProtocol = try TLS13ApplicationProtocol(
      identifier: ascii("dtls-p256").span
    )
    var client = try DTLS13ClientHandshake.make(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyExchange: TLS13P256ClientKeyExchange.generate(
        using: FixedEntropy(
          bytes: ContiguousArray(repeating: 0x21, count: 32)
        )
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      applicationProtocols: [applicationProtocol],
      verificationInstant: instant,
      maximumDatagramByteCount: 1_200
    )
    var server = try DTLS13ServerHandshake.make(
      random: ContiguousArray(repeating: 0x31, count: 32).span,
      keyExchange: TLS13P256ServerKeyExchange.generate(
        using: FixedEntropy(
          bytes: ContiguousArray(repeating: 0x41, count: 32)
        )
      ),
      keyExchangeEntropy: FixedEntropy(
        bytes: ContiguousArray(repeating: 0x51, count: 32)
      ),
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      cookieProtector: cookieProtector,
      applicationProtocolSelector:
        try ServerPreferredTLS13ApplicationProtocolSelector(
          supportedProtocols: [applicationProtocol]
        ),
      maximumDatagramByteCount: 1_200
    )

    let clientInitialDatagrams = try emittedDatagrams(client.start())
    let clientInitial = try XCTUnwrap(clientInitialDatagrams.first)
    let retryDatagrams = try emittedDatagrams(
      server.receiveDatagram(clientInitial.span, from: serverPeer)
    )
    let retry = try XCTUnwrap(retryDatagrams.first)
    let clientRetryDatagrams = try emittedDatagrams(
      client.receiveDatagram(retry.span)
    )
    let clientRetry = try XCTUnwrap(clientRetryDatagrams.first)
    let serverDatagrams = try emittedDatagrams(
      server.receiveDatagram(clientRetry.span, from: serverPeer)
    )

    var clientFinalDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in serverDatagrams {
      clientFinalDatagrams.append(
        contentsOf: try emittedDatagrams(client.receiveDatagram(datagram.span))
      )
    }
    var serverAcknowledgmentDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in clientFinalDatagrams {
      serverAcknowledgmentDatagrams.append(
        contentsOf: try emittedDatagrams(
          server.receiveDatagram(datagram.span, from: serverPeer)
        )
      )
    }
    for datagram in serverAcknowledgmentDatagrams {
      _ = try client.receiveDatagram(datagram.span)
    }

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(client.isHandshakeConfirmed)
    XCTAssertTrue(server.isEstablished)
    XCTAssertEqual(client.negotiatedApplicationProtocol, applicationProtocol)
    XCTAssertEqual(server.negotiatedApplicationProtocol, applicationProtocol)
  }

  func testDTLS13SRTPNegotiatesServerPreferenceAndExportsIdenticalMaterial() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let serverPeer = try DTLS13PeerContext(
      identity: ascii("srtp-client-endpoint").span,
      receivedAt: instant
    )
    let cookieProtector = try HMACSHA256DTLS13CookieProtector(
      key: ContiguousArray(repeating: 0xA5, count: 32).span
    )
    let masterKeyIdentifier = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let clientConfiguration = try DTLSSRTPClientConfiguration(
      protectionProfiles: [.aeadAES128GCM, .aeadAES256GCM],
      masterKeyIdentifier: masterKeyIdentifier.span,
      requiresMasterKeyIdentifierEcho: true
    )
    let serverConfiguration = try DTLSSRTPServerConfiguration(
      protectionProfiles: [.aeadAES256GCM, .aeadAES128GCM]
    )
    var client = try DTLS13ClientHandshake.make(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x21, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: instant,
      srtpConfiguration: clientConfiguration
    )
    var server = try DTLS13ServerHandshake.make(
      random: ContiguousArray(repeating: 0x31, count: 32).span,
      ephemeralKey: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x41, count: 32).span
      ),
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      cookieProtector: cookieProtector,
      srtpConfiguration: serverConfiguration
    )

    let clientInitial = try XCTUnwrap(
      try emittedDatagrams(client.start()).first
    )
    let retry = try XCTUnwrap(
      try emittedDatagrams(
        server.receiveDatagram(clientInitial.span, from: serverPeer)
      ).first
    )
    let clientRetry = try XCTUnwrap(
      try emittedDatagrams(client.receiveDatagram(retry.span)).first
    )
    let serverDatagrams = try emittedDatagrams(
      server.receiveDatagram(clientRetry.span, from: serverPeer)
    )
    var clientFinalDatagrams = ContiguousArray<OwnedBytes>()
    for datagram in serverDatagrams {
      clientFinalDatagrams.append(
        contentsOf: try emittedDatagrams(client.receiveDatagram(datagram.span))
      )
    }
    for datagram in clientFinalDatagrams {
      _ = try server.receiveDatagram(datagram.span, from: serverPeer)
    }

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertEqual(client.srtpProtectionProfile, .aeadAES256GCM)
    XCTAssertEqual(server.srtpProtectionProfile, .aeadAES256GCM)
    XCTAssertEqual(
      client.srtpMasterKeyIdentifier,
      OwnedBytes(copying: masterKeyIdentifier.span)
    )
    XCTAssertEqual(client.srtpMasterKeyIdentifier, server.srtpMasterKeyIdentifier)

    let clientMaterial = try client.exportSRTPKeyingMaterial()
    let serverMaterial = try server.exportSRTPKeyingMaterial()
    let clientWriteKey = clientMaterial.withClientWriteMasterKey(copy)
    let serverViewOfClientWriteKey = serverMaterial.withClientWriteMasterKey(copy)
    let clientWriteSalt = clientMaterial.withClientWriteMasterSalt(copy)
    let serverViewOfClientWriteSalt = serverMaterial.withClientWriteMasterSalt(copy)
    let serverWriteKey = serverMaterial.withServerWriteMasterKey(copy)
    let clientViewOfServerWriteKey = clientMaterial.withServerWriteMasterKey(copy)
    let serverWriteSalt = serverMaterial.withServerWriteMasterSalt(copy)
    let clientViewOfServerWriteSalt = clientMaterial.withServerWriteMasterSalt(copy)
    XCTAssertEqual(clientWriteKey, serverViewOfClientWriteKey)
    XCTAssertEqual(clientWriteSalt, serverViewOfClientWriteSalt)
    XCTAssertEqual(serverWriteKey, clientViewOfServerWriteKey)
    XCTAssertEqual(serverWriteSalt, clientViewOfServerWriteSalt)
    XCTAssertEqual(clientWriteKey.count, 32)
    XCTAssertEqual(clientWriteSalt.count, 12)
  }

  func testECHAcceptedHandshakeUsesInnerTranscriptAndCompletes() throws {
    var pair = try makeECHCorePair(serverConfigurationMatches: true)

    let clientOutput = try pair.client.start()
    let parsedOuter = try TLS13HandshakeCodec.parseClientHello(clientOutput.bytes.span)
    XCTAssertEqual(parsedOuter.serverName, OwnedBytes(copying: ascii("public.example").span))

    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientOutput.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try pair.client.receiveHandshakeMessage(flight.serverHello.span, at: .initial)

    var clientFinished: OwnedBytes?
    for message in try TLS13HandshakeCodec.splitMessages(flight.encryptedFlight.span) {
      let output = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
        }
      }
    }
    guard let clientFinished else { return XCTFail("missing ClientFinished") }
    _ = try pair.server.receiveHandshakeMessage(clientFinished.span, at: .handshake)

    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
  }

  func testECHAcceptedHelloRetryRequestReusesHPKEContextAndCompletes() throws {
    var pair = try makeECHCorePair(serverConfigurationMatches: true)
    let cookie = ascii("ech-retry-cookie")

    let firstClientOutput = try pair.client.start()
    let selectedCipherSuite = try pair.server.prepareHelloRetryRequest(
      for: firstClientOutput.bytes.span
    )
    XCTAssertEqual(selectedCipherSuite, .aes128GCM_SHA256)
    let retryOutput = try pair.server.completeHelloRetryRequest(
      cookie: cookie.span
    )
    let parsedRetry = try TLS13HandshakeCodec.parseHelloRetryRequest(
      retryOutput.bytes.span
    )
    XCTAssertNotNil(parsedRetry.echAcceptanceConfirmation)

    let secondClientOutput = try pair.client.receiveHandshakeMessage(
      retryOutput.bytes.span,
      at: .initial
    )
    let parsedSecondOuter = try ECHClientHelloCodec.parseOuter(
      secondClientOutput.bytes.span
    )
    XCTAssertEqual(parsedSecondOuter.encapsulationRange.count, 0)

    let serverOutput = try pair.server.receiveHandshakeMessage(
      secondClientOutput.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(
      pair: &pair,
      serverOutput: serverOutput
    )
  }

  func testECHAcceptedPSKHelloRetryRequestRecomputesBinderAndCompletes() throws {
    var pair = try makeECHResumptionCorePair()
    let cookie = ascii("ech-psk-retry-cookie")

    let firstClientOutput = try pair.client.start()
    _ = try pair.server.prepareHelloRetryRequest(
      for: firstClientOutput.bytes.span
    )
    let retryOutput = try pair.server.completeHelloRetryRequest(
      cookie: cookie.span
    )
    let secondClientOutput = try pair.client.receiveHandshakeMessage(
      retryOutput.bytes.span,
      at: .initial
    )
    let serverOutput = try pair.server.receiveHandshakeMessage(
      secondClientOutput.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(
      pair: &pair,
      serverOutput: serverOutput
    )
  }

  func testHelloRetryRequestRejectsEarlyDataAndRemovesSecondOffer() throws {
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let receivedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 0
    )
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let master = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    var serverState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7,
      maximumEarlyDataByteCount: 1_024
    )
    let serverPSK = try serverState.consumePSK()
    let clientState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7,
      maximumEarlyDataByteCount: 1_024
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: issuedAt,
      resumptionState: clientState,
      earlyDataConfiguration: try TLS13EarlyDataClientConfiguration(
        maximumByteCount: 1_024
      )
    )
    var server = try serverPSK.withBorrowedBytes { psk in
      try TLS13ServerHandshakeCore(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x22, count: 32).span
        ),
        certificateDER: deterministicCertificate().span,
        signingKey: TLS13SigningKey(
          ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        ),
        verificationInstant: receivedAt,
        resumptionIdentity: ticket.span,
        resumptionPSK: psk,
        resumptionIssuedAt: issuedAt,
        resumptionLifetime: 3_600,
        resumptionAgeAdd: 7,
        resumptionMaximumEarlyDataByteCount: 1_024,
        earlyDataConfiguration: try TLS13EarlyDataServerConfiguration(
          maximumByteCount: 1_024,
          replayProtector: CoreAcceptingEarlyDataReplayProtector()
        )
      )
    }

    let firstClientOutput = try client.start()
    XCTAssertEqual(client.earlyDataState, .offered)
    let firstClientHello = try TLS13HandshakeCodec.parseClientHello(
      firstClientOutput.bytes.span
    )
    XCTAssertTrue(firstClientHello.offersEarlyData)

    _ = try server.prepareHelloRetryRequest(
      for: firstClientOutput.bytes.span
    )
    XCTAssertEqual(server.earlyDataState, .rejected)
    let retryOutput = try server.completeHelloRetryRequest(
      cookie: ascii("early-data-retry-cookie").span
    )
    XCTAssertTrue(retryOutput.actions.contains(.earlyDataRejected))

    let secondClientOutput = try client.receiveHandshakeMessage(
      retryOutput.bytes.span,
      at: .initial
    )
    XCTAssertEqual(client.earlyDataState, .rejected)
    XCTAssertTrue(secondClientOutput.actions.contains(.earlyDataRejected))
    let secondClientHello = try TLS13HandshakeCodec.parseClientHello(
      secondClientOutput.bytes.span
    )
    XCTAssertFalse(secondClientHello.offersEarlyData)
  }

  func testClientRejectsSecondHelloRetryRequest() throws {
    var pair = try makeCorePair()
    let firstClientOutput = try pair.client.start()
    _ = try pair.server.prepareHelloRetryRequest(
      for: firstClientOutput.bytes.span
    )
    let retryOutput = try pair.server.completeHelloRetryRequest(
      cookie: ascii("single-retry-cookie").span
    )
    _ = try pair.client.receiveHandshakeMessage(
      retryOutput.bytes.span,
      at: .initial
    )
    do {
      _ = try pair.client.receiveHandshakeMessage(
        retryOutput.bytes.span,
        at: .initial
      )
      XCTFail("second HelloRetryRequest was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .handshake(
          .unexpectedMessage(type: TLS13HandshakeCodec.serverHelloType)
        )
      )
    }
  }

  func testServerSelectsItsPreferredSuiteFromClientOfferVector() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: deterministicCertificate().span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      keyShare: try X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ).publicKey().span,
      cipherSuites: [.chacha20Poly1305_SHA256, .aes128GCM_SHA256]
    )

    let selected = try server.prepareHelloRetryRequest(
      for: clientHello.span
    )

    XCTAssertEqual(selected, .aes128GCM_SHA256)
  }

  func testECHAcceptedPSKResumptionUsesInnerBinderAndCompletes() throws {
    var pair = try makeECHResumptionCorePair()

    let clientOutput = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientOutput.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    let serverHello = try TLS13HandshakeCodec.parseServerHello(
      flight.serverHello.span
    )
    XCTAssertTrue(serverHello.selectedPreSharedKey)

    _ = try pair.client.receiveHandshakeMessage(flight.serverHello.span, at: .initial)
    let messages = try TLS13HandshakeCodec.splitMessages(flight.encryptedFlight.span)
    XCTAssertEqual(messages.count, 2)
    XCTAssertEqual(messages[0][0], TLS13HandshakeCodec.encryptedExtensionsType)
    XCTAssertEqual(messages[1][0], TLS13HandshakeCodec.finishedType)

    var clientFinished: OwnedBytes?
    for message in messages {
      let output = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
        }
      }
    }
    guard let clientFinished else { return XCTFail("missing ClientFinished") }
    _ = try pair.server.receiveHandshakeMessage(clientFinished.span, at: .handshake)

    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
  }

  func testECHRejectionAuthenticatesPublicNameAndReturnsRetryConfigurations() throws {
    var pair = try makeECHCorePair(serverConfigurationMatches: false)

    let clientOutput = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientOutput.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try pair.client.receiveHandshakeMessage(flight.serverHello.span, at: .initial)

    var messages = try TLS13HandshakeCodec.splitMessages(flight.encryptedFlight.span)
    XCTAssertEqual(messages.count, 4)
    let serverFinished = messages.removeLast()
    for message in messages {
      _ = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
    }
    do {
      _ = try pair.client.receiveHandshakeMessage(serverFinished.span, at: .handshake)
      XCTFail("ECH rejection completed as an origin handshake")
    } catch let error {
      guard case .echRequired(let retryConfigurations) = error else {
        return XCTFail("unexpected ECH rejection error: \(error)")
      }
      XCTAssertEqual(retryConfigurations?.configurations.count, 1)
      XCTAssertEqual(retryConfigurations?.configurations.first?.configID, 18)
    }
    XCTAssertFalse(pair.client.isEstablished)
  }

  func testECHRejectedHelloRetryRequestContinuesWithOuterAndFailsClosed() throws {
    var pair = try makeECHCorePair(serverConfigurationMatches: false)
    let firstClientOutput = try pair.client.start()
    _ = try pair.server.prepareHelloRetryRequest(
      for: firstClientOutput.bytes.span
    )
    let retryOutput = try pair.server.completeHelloRetryRequest(
      cookie: ascii("outer-retry-cookie").span
    )
    let parsedRetry = try TLS13HandshakeCodec.parseHelloRetryRequest(
      retryOutput.bytes.span
    )
    XCTAssertNil(parsedRetry.echAcceptanceConfirmation)

    let secondClientOutput = try pair.client.receiveHandshakeMessage(
      retryOutput.bytes.span,
      at: .initial
    )
    let serverOutput = try pair.server.receiveHandshakeMessage(
      secondClientOutput.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try pair.client.receiveHandshakeMessage(
      flight.serverHello.span,
      at: .initial
    )
    var messages = try TLS13HandshakeCodec.splitMessages(
      flight.encryptedFlight.span
    )
    let serverFinished = messages.removeLast()
    for message in messages {
      _ = try pair.client.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    do {
      _ = try pair.client.receiveHandshakeMessage(
        serverFinished.span,
        at: .handshake
      )
      XCTFail("ECH rejection completed after HelloRetryRequest")
    } catch let error {
      guard case .echRequired(let retryConfigurations) = error else {
        return XCTFail("unexpected ECH rejection error: \(error)")
      }
      XCTAssertEqual(retryConfigurations?.configurations.first?.configID, 18)
    }
  }

  func testHybridClientServerHandshakeCompletesThroughCore() throws {
    var pair = try makeHybridCorePair()

    let clientHelloOutput = try pair.client.start()
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHelloOutput.bytes.span
    )
    XCTAssertEqual(
      parsedClientHello.offeredNamedGroups,
      [TLS13NamedGroup.x25519MLKEM768.rawValue]
    )
    XCTAssertEqual(parsedClientHello.keyShares.count, 1)
    XCTAssertEqual(parsedClientHello.keyShares[0].keyExchange.count, 1_216)

    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHelloOutput.bytes.span,
      at: .initial
    )
    guard case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
      case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
    else {
      return XCTFail("hybrid server core emitted an invalid effect order")
    }
    let serverHello = OwnedBytes(
      copying: try serverOutput.bytes.span(in: serverHelloRange)
    )
    let parsedServerHello = try TLS13HandshakeCodec.parseServerHello(serverHello.span)
    XCTAssertEqual(parsedServerHello.namedGroup, .x25519MLKEM768)
    XCTAssertEqual(parsedServerHello.keyShare.count, 1_120)
    _ = try pair.client.receiveHandshakeMessage(serverHello.span, at: .initial)

    let serverFlight = try serverOutput.bytes.span(in: serverFlightRange)
    let messages = try TLS13HandshakeCodec.splitMessages(serverFlight)
    var clientFinished: OwnedBytes?
    for message in messages {
      let output = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
        }
      }
    }
    guard let clientFinished else {
      return XCTFail("hybrid client core did not emit Finished")
    }
    _ = try pair.server.receiveHandshakeMessage(clientFinished.span, at: .handshake)

    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
  }

  func testServerCoreRejectsUnexpectedNamedGroup() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientKey,
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: instant
    )
    let hybridServer = try TLS13X25519MLKEM768ServerKeyExchange.generate(
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
    )
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      keyExchange: hybridServer,
      keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
      certificateDER: deterministicCertificate().span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    do {
      _ = try server.receiveHandshakeMessage(clientHello.bytes.span, at: .initial)
      XCTFail("server accepted an unexpected named group")
    } catch {
      XCTAssertEqual(
        error,
        .keyExchange(
          .unexpectedNamedGroup(
            expected: .x25519MLKEM768,
            actual: .x25519
          ))
      )
    }
  }

  func testRecordIndependentClientServerHandshakeCompletesWithMatchingSecrets() throws {
    var pair = try makeCorePair()

    let clientHelloOutput = try pair.client.start()
    guard
      case .emitHandshakeBytes(.initial, let clientHelloRange) =
        clientHelloOutput.actions.first
    else {
      return XCTFail("missing ClientHello action")
    }
    let clientHello = OwnedBytes(
      copying: try clientHelloOutput.bytes.span(in: clientHelloRange)
    )

    var serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.span,
      at: .initial
    )
    guard serverOutput.actions.count == 4,
      case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
      case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
    else {
      return XCTFail("server core emitted an invalid effect order")
    }
    let serverHello = OwnedBytes(
      copying: try serverOutput.bytes.span(in: serverHelloRange)
    )
    let serverFlight = OwnedBytes(
      copying: try serverOutput.bytes.span(in: serverFlightRange)
    )
    var serverHandshakeSecrets: SecretSnapshot?
    var serverApplicationSecrets: SecretSnapshot?
    while let effect = try serverOutput.nextEffect() {
      switch consume effect {
      case .trafficSecrets(.handshake, let secrets):
        serverHandshakeSecrets = copySecrets(secrets)
      case .trafficSecrets(.application, let secrets):
        serverApplicationSecrets = copySecrets(secrets)
      case .action:
        break
      case .earlyTrafficSecret:
        return XCTFail("unexpected early traffic secret")
      case .trafficSecrets:
        return XCTFail("unexpected traffic-secret epoch")
      }
    }

    var clientServerHelloOutput = try pair.client.receiveHandshakeMessage(
      serverHello.span,
      at: .initial
    )
    var clientHandshakeSecrets: SecretSnapshot?
    while let effect = try clientServerHelloOutput.nextEffect() {
      switch consume effect {
      case .trafficSecrets(.handshake, let secrets):
        clientHandshakeSecrets = copySecrets(secrets)
      case .action:
        break
      case .earlyTrafficSecret:
        return XCTFail("unexpected early traffic secret")
      case .trafficSecrets:
        return XCTFail("unexpected traffic-secret epoch")
      }
    }
    XCTAssertEqual(clientHandshakeSecrets, serverHandshakeSecrets)

    let messages = try TLS13HandshakeCodec.splitMessages(serverFlight.span)
    var clientFinished: OwnedBytes?
    var clientApplicationSecrets: SecretSnapshot?
    for message in messages {
      var output = try pair.client.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(
            copying: try output.bytes.span(in: range)
          )
          XCTAssertEqual(
            output.actions,
            [
              .emitHandshakeBytes(epoch: .handshake, bytes: range),
              .installTrafficSecrets(epoch: .application),
              .handshakeComplete,
            ]
          )
        }
      }
      while let effect = try output.nextEffect() {
        switch consume effect {
        case .trafficSecrets(.application, let secrets):
          clientApplicationSecrets = copySecrets(secrets)
        case .action:
          break
        case .earlyTrafficSecret:
          return XCTFail("unexpected early traffic secret")
        case .trafficSecrets:
          return XCTFail("unexpected traffic-secret epoch")
        }
      }
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertEqual(clientApplicationSecrets, serverApplicationSecrets)
    guard let clientFinished else {
      return XCTFail("missing ClientFinished")
    }

    var confirmation = try pair.server.receiveHandshakeMessage(
      clientFinished.span,
      at: .handshake
    )
    var completed = false
    var confirmed = false
    while let effect = try confirmation.nextEffect() {
      switch consume effect {
      case .action(.handshakeComplete): completed = true
      case .action(.handshakeConfirmed): confirmed = true
      case .action: break
      case .earlyTrafficSecret: break
      case .trafficSecrets: break
      }
    }
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertTrue(completed)
    XCTAssertTrue(confirmed)
  }

  func testRequiredClientAuthenticationCompletesAndExposesIdentity() throws {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .required,
      includeClientIdentity: true
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(
      messages.map { $0[0] },
      [
        TLS13HandshakeCodec.certificateType,
        TLS13HandshakeCodec.certificateVerifyType,
        TLS13HandshakeCodec.finishedType,
      ]
    )
    XCTAssertNil(pair.server.authenticatedClientIdentity)

    var messageIndex = 0
    for message in messages {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
      if messageIndex < messages.count - 1 {
        XCTAssertNil(pair.server.authenticatedClientIdentity)
      }
      messageIndex += 1
    }

    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    let authenticated = try XCTUnwrap(
      pair.server.authenticatedClientIdentity
    )
    XCTAssertEqual(authenticated.certificateMessage.entries.count, 1)
    let authenticatedCertificate =
      authenticated.certificateMessage.entries[0].certificate
    XCTAssertEqual(
      copy(authenticatedCertificate.span),
      deterministicCertificate()
    )
  }

  func testP256ECDSAClientAuthenticationCompletesAndExposesIdentity() throws {
    var pair = try makeP256ClientAuthenticationCorePair()
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    let certificateVerifyMessage = messages[1]
    let certificateVerify = try TLS13HandshakeCodec
      .parseCertificateVerifyWithScheme(certificateVerifyMessage.span)
    XCTAssertEqual(certificateVerify.signatureScheme, .ecdsaP256SHA256)
    for message in messages {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }

    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNotNil(pair.server.authenticatedClientIdentity)
  }

  func testOptionalClientAuthenticationAcceptsEmptyCertificate() throws {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .optional,
      includeClientIdentity: false
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(messages.count, 2)
    let emptyCertificateMessage = messages[0]
    let certificate = try TLS13HandshakeCodec.parseCertificateMessage(
      emptyCertificateMessage.span
    )
    XCTAssertTrue(certificate.entries.isEmpty)

    for message in messages {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testRequiredClientAuthenticationRejectsEmptyCertificate() throws {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .required,
      includeClientIdentity: false
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(messages.count, 2)
    let emptyCertificateMessage = messages[0]

    do {
      _ = try pair.server.receiveHandshakeMessage(
        emptyCertificateMessage.span,
        at: .handshake
      )
      XCTFail("required client authentication accepted an empty Certificate")
    } catch {
      XCTAssertEqual(error, .clientCertificateRequired)
    }
    XCTAssertFalse(pair.server.isEstablished)
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testClientAuthenticationRejectsTamperedCertificateVerify() throws {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .required,
      includeClientIdentity: true
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(messages.count, 3)
    let certificateMessage = messages[0]
    let certificateVerifyMessage = messages[1]
    _ = try pair.server.receiveHandshakeMessage(
      certificateMessage.span,
      at: .handshake
    )
    var tampered = ContiguousArray(copy(certificateVerifyMessage.span))
    tampered[tampered.count - 1] ^= 0x01

    do {
      _ = try pair.server.receiveHandshakeMessage(
        tampered.span,
        at: .handshake
      )
      XCTFail("server accepted a tampered client CertificateVerify")
    } catch {
      XCTAssertEqual(error, .certificateVerifyFailure)
    }
    XCTAssertFalse(pair.server.isEstablished)
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testPostHandshakeClientAuthenticationCompletesAndExposesIdentity()
    throws
  {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .required,
      includeClientIdentity: true,
      timing: .postHandshake
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(pair: &pair, serverOutput: serverOutput)
    XCTAssertNil(pair.server.authenticatedClientIdentity)

    let context: ContiguousArray<UInt8> = [0xA1, 0xB2, 0xC3, 0xD4]
    let requestOutput: TLS13HandshakeCoreOutput
    do {
      requestOutput = try pair.server
        .requestPostHandshakeClientAuthentication(requestContext: context.span)
    } catch let error {
      XCTFail("server request failed: \(String(reflecting: error))")
      return
    }
    let request = try emittedApplicationHandshakeBytes(requestOutput)
    let clientTransition: TLS13HandshakeCoreTransition
    do {
      clientTransition = try pair.client
        .receivePostHandshakeAuthenticationRequestStep(request.span)
    } catch let error {
      XCTFail("client response failed: \(String(reflecting: error))")
      return
    }
    let clientOutput: TLS13HandshakeCoreOutput
    switch consume clientTransition {
    case .output(let output):
      clientOutput = output
    case .suspended:
      return XCTFail("local post-handshake identity unexpectedly suspended")
    }
    let clientFlight = try emittedApplicationHandshakeBytes(clientOutput)
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(
      messages.map { $0[0] },
      [
        TLS13HandshakeCodec.certificateType,
        TLS13HandshakeCodec.certificateVerifyType,
        TLS13HandshakeCodec.finishedType,
      ]
    )
    for (index, message) in messages.enumerated() {
      do {
        _ = try pair.server.receiveHandshakeMessage(
          message.span,
          at: .application
        )
      } catch let error {
        XCTFail(
          "server rejected post-handshake message \(index): "
            + String(reflecting: error)
        )
        return
      }
      if index < messages.count - 1 {
        XCTAssertNil(pair.server.authenticatedClientIdentity)
      }
    }
    XCTAssertNotNil(pair.server.authenticatedClientIdentity)

    do {
      _ = try pair.server.requestPostHandshakeClientAuthentication(
        requestContext: context.span
      )
      XCTFail("reused post-handshake request context was accepted")
    } catch let error {
      XCTAssertEqual(error, .invalidConfiguration)
    }
  }

  func testOptionalPostHandshakeClientAuthenticationAcceptsEmptyCertificate()
    throws
  {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .optional,
      includeClientIdentity: false,
      timing: .postHandshake
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(pair: &pair, serverOutput: serverOutput)

    let context: ContiguousArray<UInt8> = [0x19, 0x27]
    let requestOutput = try pair.server
      .requestPostHandshakeClientAuthentication(requestContext: context.span)
    let request = try emittedApplicationHandshakeBytes(requestOutput)
    let transition = try pair.client
      .receivePostHandshakeAuthenticationRequestStep(request.span)
    let clientOutput: TLS13HandshakeCoreOutput
    switch consume transition {
    case .output(let output):
      clientOutput = output
    case .suspended:
      return XCTFail("empty post-handshake response unexpectedly suspended")
    }
    let clientFlight = try emittedApplicationHandshakeBytes(clientOutput)
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(
      messages.map { $0[0] },
      [TLS13HandshakeCodec.certificateType, TLS13HandshakeCodec.finishedType]
    )
    for message in messages {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .application
      )
    }
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testPostHandshakeClientAuthenticationRejectsTamperedFinished() throws {
    var pair = try makeClientAuthenticationCorePair(
      requirement: .required,
      includeClientIdentity: true,
      timing: .postHandshake
    )
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(pair: &pair, serverOutput: serverOutput)

    let context: ContiguousArray<UInt8> = [0x55, 0x66, 0x77]
    let requestOutput = try pair.server
      .requestPostHandshakeClientAuthentication(requestContext: context.span)
    let request = try emittedApplicationHandshakeBytes(requestOutput)
    let transition = try pair.client
      .receivePostHandshakeAuthenticationRequestStep(request.span)
    let clientOutput: TLS13HandshakeCoreOutput
    switch consume transition {
    case .output(let output):
      clientOutput = output
    case .suspended:
      return XCTFail("local post-handshake identity unexpectedly suspended")
    }
    let clientFlight = try emittedApplicationHandshakeBytes(clientOutput)
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    let certificateMessage = messages[0]
    let certificateVerifyMessage = messages[1]
    let finishedMessage = messages[2]
    _ = try pair.server.receiveHandshakeMessage(
      certificateMessage.span,
      at: .application
    )
    _ = try pair.server.receiveHandshakeMessage(
      certificateVerifyMessage.span,
      at: .application
    )
    var tamperedFinished = ContiguousArray(copy(finishedMessage.span))
    tamperedFinished[tamperedFinished.count - 1] ^= 0x01
    do {
      _ = try pair.server.receiveHandshakeMessage(
        tamperedFinished.span,
        at: .application
      )
      XCTFail("tampered post-handshake Finished was accepted")
    } catch let error {
      XCTAssertEqual(error, .certificateVerifyFailure)
    }
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testRFC5280CertificateValidatorAuthenticatesHandshake() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = try deterministicCertificate(
      dnsNames: ["server.example"]
    )
    let certificate = try X509Certificate(der: certificateDER.span)
    let validator = try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [certificate]
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: validator,
      serverName: ascii("server.example").span,
      verificationInstant: instant
    )
    let entry = try TLS13CertificateEntry(certificateDER: certificateDER.span)
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateEntries: [entry],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    let serverOutput = try server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try client.receiveHandshakeMessage(flight.serverHello.span, at: .initial)

    var clientFinished: OwnedBytes?
    for message in try TLS13HandshakeCodec.splitMessages(
      flight.encryptedFlight.span
    ) {
      let output = try client.receiveHandshakeMessage(message.span, at: .handshake)
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
        }
      }
    }
    guard let clientFinished else { return XCTFail("missing ClientFinished") }
    _ = try server.receiveHandshakeMessage(clientFinished.span, at: .handshake)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testRFC5280CertificateValidatorRejectsWrongServerName() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = try deterministicCertificate(
      dnsNames: ["server.example"]
    )
    let certificate = try X509Certificate(der: certificateDER.span)
    let validator = try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [certificate]
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: validator,
      serverName: ascii("wrong.example").span,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    let serverOutput = try server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try client.receiveHandshakeMessage(flight.serverHello.span, at: .initial)
    let messages = try TLS13HandshakeCodec.splitMessages(
      flight.encryptedFlight.span
    )
    XCTAssertEqual(messages[0][0], TLS13HandshakeCodec.encryptedExtensionsType)
    XCTAssertEqual(messages[1][0], TLS13HandshakeCodec.certificateType)
    let encryptedExtensions = messages[0]
    let certificateMessage = messages[1]
    _ = try client.receiveHandshakeMessage(
      encryptedExtensions.span,
      at: .handshake
    )
    do {
      _ = try client.receiveHandshakeMessage(
        certificateMessage.span,
        at: .handshake
      )
      XCTFail("wrong server name was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .certificateValidation(
          .path(.identity(.noMatchingSubjectAlternativeName))
        )
      )
    }
  }

  func testClientRejectsTamperedRecordIndependentServerFinished() throws {
    var pair = try makeCorePair()
    let clientHelloOutput = try pair.client.start()
    let clientHello = clientHelloOutput.bytes
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.span,
      at: .initial
    )
    guard case .emitHandshakeBytes(.initial, let serverHelloRange) = serverOutput.actions[0],
      case .emitHandshakeBytes(.handshake, let serverFlightRange) = serverOutput.actions[2]
    else {
      return XCTFail("missing server flight")
    }
    let serverHello = OwnedBytes(copying: try serverOutput.bytes.span(in: serverHelloRange))
    let serverFlight = OwnedBytes(copying: try serverOutput.bytes.span(in: serverFlightRange))
    _ = try pair.client.receiveHandshakeMessage(serverHello.span, at: .initial)
    var messages = try TLS13HandshakeCodec.splitMessages(serverFlight.span)
    guard let originalFinished = messages.popLast() else {
      return XCTFail("missing ServerFinished")
    }
    for message in messages {
      _ = try pair.client.receiveHandshakeMessage(message.span, at: .handshake)
    }
    var tampered = copy(originalFinished.span)
    tampered[tampered.count - 1] ^= 0x01
    do {
      _ = try pair.client.receiveHandshakeMessage(tampered.span, at: .handshake)
      XCTFail("tampered ServerFinished was accepted")
    } catch {
      XCTAssertEqual(error, .certificateVerifyFailure)
    }
    XCTAssertFalse(pair.client.isEstablished)
  }

  func testCoreRejectsMessageAtWrongEpochAndEntersFailedState() throws {
    var pair = try makeCorePair()
    let clientHelloOutput = try pair.client.start()
    do {
      _ = try pair.server.receiveHandshakeMessage(
        clientHelloOutput.bytes.span,
        at: .handshake
      )
      XCTFail("ClientHello was accepted at the handshake epoch")
    } catch {
      XCTAssertEqual(error, .malformedInput)
    }
    do {
      _ = try pair.server.receiveHandshakeMessage(
        clientHelloOutput.bytes.span,
        at: .initial
      )
      XCTFail("a failed core accepted another message")
    } catch {
      XCTAssertEqual(error, .invalidState)
    }
  }

  func testRecordIndependentPSKResumptionOmitsCertificateFlight() throws {
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let receivedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 0
    )
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let master = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    var serverState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7
    )
    let serverPSK = try serverState.consumePSK()
    let clientState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      serverName: ascii("resumed.example").span,
      verificationInstant: issuedAt,
      resumptionState: clientState
    )
    var server = try serverPSK.withBorrowedBytes { psk in
      try TLS13ServerHandshakeCore(
        random: ContiguousArray(repeating: 0x02, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x22, count: 32).span
        ),
        certificateDER: deterministicCertificate().span,
        signingKey: TLS13SigningKey(
          ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        ),
        verificationInstant: receivedAt,
        resumptionIdentity: ticket.span,
        resumptionPSK: psk,
        resumptionIssuedAt: issuedAt,
        resumptionLifetime: 3_600,
        resumptionAgeAdd: 7
      )
    }

    let clientHello = try client.start()
    let parsed = try TLS13HandshakeCodec.parseClientHello(clientHello.bytes.span)
    XCTAssertNotNil(parsed.preSharedKey)
    XCTAssertEqual(parsed.serverName, OwnedBytes(copying: ascii("resumed.example").span))
    let serverOutput = try server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    guard case .emitHandshakeBytes(.initial, let helloRange) = serverOutput.actions[0],
      case .emitHandshakeBytes(.handshake, let flightRange) = serverOutput.actions[2]
    else {
      return XCTFail("missing resumed server flight")
    }
    let serverHello = OwnedBytes(copying: try serverOutput.bytes.span(in: helloRange))
    let flight = OwnedBytes(copying: try serverOutput.bytes.span(in: flightRange))
    let messages = try TLS13HandshakeCodec.splitMessages(flight.span)
    XCTAssertEqual(messages.count, 2)
    XCTAssertEqual(messages[0][0], TLS13HandshakeCodec.encryptedExtensionsType)
    XCTAssertEqual(messages[1][0], TLS13HandshakeCodec.finishedType)

    _ = try client.receiveHandshakeMessage(serverHello.span, at: .initial)
    var clientFinished: OwnedBytes?
    for message in messages {
      let output = try client.receiveHandshakeMessage(message.span, at: .handshake)
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(copying: try output.bytes.span(in: range))
        }
      }
    }
    guard let clientFinished else { return XCTFail("missing ClientFinished") }
    _ = try server.receiveHandshakeMessage(clientFinished.span, at: .handshake)
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testCoreOutputRejectsInitialTrafficSecretInstallation() throws {
    do {
      let output = try TLS13HandshakeCoreOutput(
        bytes: OwnedBytes(),
        actions: [.installTrafficSecrets(epoch: .initial)]
      )
      _ = output.remainingEffectCount
      XCTFail("initial traffic-secret installation was accepted")
    } catch {
      XCTAssertEqual(error, .missingTrafficSecrets(.initial))
    }
  }

  func testClientExternalTrustSuspendsCorrelatesAndCompletesHandshake() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      externalServerTrust: TLS13ExternalServerTrust(),
      serverName: ascii("server.example").span,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )

    let clientInitial = try client.start()
    let serverOutput = try server.receiveHandshakeMessage(
      clientInitial.bytes.span,
      at: .initial
    )
    let serverFlight = try splitServerOutput(serverOutput)
    _ = try client.receiveHandshakeMessage(
      serverFlight.serverHello.span,
      at: .initial
    )

    var request: TLS13PeerTrustEvaluationRequest?
    var clientFinalFlight: OwnedBytes?
    let serverMessages = try TLS13HandshakeCodec.splitMessages(
      serverFlight.encryptedFlight.span
    )
    for message in serverMessages {
      if message[0] == TLS13HandshakeCodec.certificateType {
        let transition = try client.receiveHandshakeMessageStep(
          message.span,
          at: .handshake
        )
        switch consume transition {
        case .suspended(.peerTrustEvaluation(let value)):
          request = value
        case .suspended:
          XCTFail("unexpected external capability request")
        case .output(let output):
          _ = output.remainingEffectCount
          XCTFail("certificate validation did not suspend")
        }
      } else if message[0] == TLS13HandshakeCodec.finishedType {
        let output = try client.receiveHandshakeMessage(
          message.span,
          at: .handshake
        )
        for action in output.actions {
          if case .emitHandshakeBytes(.handshake, let range) = action {
            clientFinalFlight = OwnedBytes(
              copying: try output.bytes.span(in: range)
            )
          }
        }
      } else {
        _ = try client.receiveHandshakeMessage(message.span, at: .handshake)
      }

      if let pendingRequest = request {
        XCTAssertEqual(pendingRequest.peer, .server)
        XCTAssertEqual(
          pendingRequest.serverName,
          OwnedBytes(copying: ascii("server.example").span)
        )
        XCTAssertEqual(pendingRequest.certificateMessage.entries.count, 1)

        let wrongEngine = TLS13CapabilityToken(
          engineIdentifier: OwnedBytes(copying: ascii("another-engine").span),
          sequence: pendingRequest.token.sequence,
          kind: pendingRequest.token.kind
        )
        do {
          _ = try client.resume(.peerTrustAccepted(wrongEngine))
          XCTFail("wrong engine response was accepted")
        } catch let error {
          guard case .capability(.wrongEngine) = error else {
            return XCTFail("unexpected wrong-engine error: \(error)")
          }
        }

        let wrongKind = TLS13CapabilityToken(
          engineIdentifier: pendingRequest.token.engineIdentifier,
          sequence: pendingRequest.token.sequence,
          kind: .signature
        )
        do {
          _ = try client.resume(.peerTrustAccepted(wrongKind))
          XCTFail("wrong capability kind was accepted")
        } catch let error {
          XCTAssertEqual(
            error,
            .capability(
              .wrongKind(
                expected: .peerTrustEvaluation,
                actual: .signature
              )
            )
          )
        }

        let resumed = try client.resume(
          .peerTrustAccepted(pendingRequest.token)
        )
        switch consume resumed {
        case .output(let output):
          XCTAssertEqual(output.remainingEffectCount, 0)
        case .suspended:
          XCTFail("accepted trust result suspended again")
        }

        do {
          _ = try client.resume(.peerTrustAccepted(pendingRequest.token))
          XCTFail("duplicate response was accepted")
        } catch let error {
          XCTAssertEqual(
            error,
            .capability(.duplicateResponse(pendingRequest.token))
          )
        }
        request = nil
      }
    }

    guard let clientFinalFlight else {
      return XCTFail("missing client final flight")
    }
    for message in try TLS13HandshakeCodec.splitMessages(clientFinalFlight.span) {
      _ = try server.receiveHandshakeMessage(message.span, at: .handshake)
    }
    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testServerExternalClientTrustSuspendsAndCompletesAuthentication() throws {
    var pair = try makeExternalClientTrustCorePair()
    let initial = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      initial.bytes.span,
      at: .initial
    )
    let clientFinalFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )

    var sawTrustRequest = false
    for message in try TLS13HandshakeCodec.splitMessages(clientFinalFlight.span) {
      if message[0] == TLS13HandshakeCodec.certificateType {
        let transition = try pair.server.receiveHandshakeMessageStep(
          message.span,
          at: .handshake
        )
        let request: TLS13PeerTrustEvaluationRequest
        switch consume transition {
        case .suspended(.peerTrustEvaluation(let value)):
          request = value
        case .suspended:
          return XCTFail("unexpected external capability request")
        case .output(let output):
          _ = output.remainingEffectCount
          return XCTFail("client certificate validation did not suspend")
        }
        XCTAssertEqual(request.peer, .client)
        XCTAssertNil(request.serverName)
        XCTAssertEqual(request.certificateMessage.entries.count, 1)
        let resumed = try pair.server.resume(
          .peerTrustAccepted(request.token)
        )
        switch consume resumed {
        case .output(let output):
          XCTAssertEqual(output.remainingEffectCount, 0)
        case .suspended:
          XCTFail("accepted client trust result suspended again")
        }
        sawTrustRequest = true
      } else {
        _ = try pair.server.receiveHandshakeMessage(
          message.span,
          at: .handshake
        )
      }
    }

    XCTAssertTrue(sawTrustRequest)
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNotNil(pair.server.authenticatedClientIdentity)
  }

  func testServerExternalClientTrustRejectionFailsHandshake() throws {
    var pair = try makeExternalClientTrustCorePair()
    let initial = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      initial.bytes.span,
      at: .initial
    )
    let clientFinalFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    let messages = try TLS13HandshakeCodec.splitMessages(clientFinalFlight.span)
    guard let certificate = messages.first,
      certificate[0] == TLS13HandshakeCodec.certificateType
    else {
      return XCTFail("missing client Certificate")
    }
    let transition = try pair.server.receiveHandshakeMessageStep(
      certificate.span,
      at: .handshake
    )
    let request: TLS13PeerTrustEvaluationRequest
    switch consume transition {
    case .suspended(.peerTrustEvaluation(let value)):
      request = value
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("client certificate validation did not suspend")
    }
    do {
      _ = try pair.server.resume(.peerTrustRejected(request.token))
      XCTFail("rejected client trust result was accepted")
    } catch let error {
      XCTAssertEqual(
        error,
        .capability(.peerTrustRejected(.client))
      )
    }
    XCTAssertFalse(pair.server.isEstablished)
    let nextMessage = messages[1]
    do {
      _ = try pair.server.receiveHandshakeMessage(
        nextMessage.span,
        at: .handshake
      )
      XCTFail("failed handshake accepted another message")
    } catch let error {
      XCTAssertEqual(error, .invalidState)
    }
  }

  func testExternalServerCredentialSelectionAndSigningCompleteHandshake() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var pair = CorePair(
      client: try TLS13ClientHandshakeCore(
        random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
        ),
        certificateValidator: try makeCertificateValidator(
          certificateDER: certificateDER
        ),
        verificationInstant: instant
      ),
      server: try TLS13ServerHandshakeCore(
        random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
        ),
        externalServerCredential: TLS13ExternalServerCredential(),
        verificationInstant: instant
      )
    )
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let credential = try TLS13CredentialDescriptor(
      identifier: ascii("server-key-1").span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )

    let clientInitial = try pair.client.start()
    let selectionTransition = try pair.server.receiveHandshakeMessageStep(
      clientInitial.bytes.span,
      at: .initial
    )
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selectionTransition {
    case .suspended(.credentialSelection(let request)):
      selectionRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("server credential selection did not suspend")
    }
    XCTAssertEqual(selectionRequest.role, .server)
    XCTAssertEqual(selectionRequest.token.sequence, 0)
    XCTAssertTrue(selectionRequest.signatureSchemes.contains(.ed25519))

    let signingTransition = try pair.server.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signingTransition {
    case .suspended(.signature(let request)):
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("server signature did not suspend")
    }
    XCTAssertEqual(signatureRequest.role, .server)
    XCTAssertEqual(signatureRequest.credentialIdentifier, credential.identifier)
    XCTAssertEqual(signatureRequest.token.sequence, 1)
    XCTAssertEqual(
      signatureRequest.token.engineIdentifier,
      selectionRequest.token.engineIdentifier
    )
    let signature = try signer.sign(message: signatureRequest.message.span)
    let outputTransition = try pair.server.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    switch consume outputTransition {
    case .output(let output):
      try completeCoreHandshake(pair: &pair, serverOutput: output)
    case .suspended:
      XCTFail("verified signature did not produce the server flight")
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
  }

  func testExternalServerCredentialUnavailableFailsExplicitly() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    var client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: deterministicCertificate()
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      externalServerCredential: TLS13ExternalServerCredential(),
      verificationInstant: instant
    )
    let initial = try client.start()
    let transition = try server.receiveHandshakeMessageStep(
      initial.bytes.span,
      at: .initial
    )
    let token: TLS13CapabilityToken
    switch consume transition {
    case .suspended(.credentialSelection(let request)):
      token = request.token
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("server credential selection did not suspend")
    }
    do {
      _ = try server.resume(.credentialUnavailable(token))
      XCTFail("missing server credential was accepted")
    } catch let error {
      XCTAssertEqual(
        error,
        .capability(.credentialUnavailable(.server))
      )
    }
    XCTAssertFalse(server.isEstablished)
  }

  func testExternalClientCredentialSelectionAndSigningCompleteAuthentication()
    throws
  {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var pair = try makeExternalClientCredentialCorePair(requirement: .required)
    let selectionRequest = try suspendClientForExternalCredential(pair: &pair)
    XCTAssertEqual(selectionRequest.role, .client)
    XCTAssertEqual(selectionRequest.token.sequence, 0)
    XCTAssertTrue(selectionRequest.signatureSchemes.contains(.ed25519))
    let credential = try TLS13CredentialDescriptor(
      identifier: ascii("client-key-1").span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    let signingTransition = try pair.client.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signingTransition {
    case .suspended(.signature(let request)):
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("client signature did not suspend")
    }
    XCTAssertEqual(signatureRequest.role, .client)
    XCTAssertEqual(signatureRequest.token.sequence, 1)
    XCTAssertEqual(
      signatureRequest.token.engineIdentifier,
      selectionRequest.token.engineIdentifier
    )
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: signatureRequest.message.span)
    let outputTransition = try pair.client.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let clientFlight: OwnedBytes
    switch consume outputTransition {
    case .output(let output):
      clientFlight = try emittedHandshakeBytes(output)
    case .suspended:
      return XCTFail("verified client signature suspended again")
    }
    for message in try TLS13HandshakeCodec.splitMessages(clientFlight.span) {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNotNil(pair.server.authenticatedClientIdentity)
  }

  func testExternalClientCredentialUnavailableEmitsEmptyCertificate() throws {
    var pair = try makeExternalClientCredentialCorePair(requirement: .optional)
    let selectionRequest = try suspendClientForExternalCredential(pair: &pair)
    let outputTransition = try pair.client.resume(
      .credentialUnavailable(selectionRequest.token)
    )
    let clientFlight: OwnedBytes
    switch consume outputTransition {
    case .output(let output):
      clientFlight = try emittedHandshakeBytes(output)
    case .suspended:
      return XCTFail("missing credential suspended again")
    }
    let messages = try TLS13HandshakeCodec.splitMessages(clientFlight.span)
    XCTAssertEqual(messages.count, 2)
    let emptyCertificateMessage = messages[0]
    let certificate = try TLS13HandshakeCodec.parseCertificateMessage(
      emptyCertificateMessage.span
    )
    XCTAssertTrue(certificate.entries.isEmpty)
    for message in messages {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
    XCTAssertNil(pair.server.authenticatedClientIdentity)
  }

  func testExternalClientCredentialRejectsInvalidSignature() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var pair = try makeExternalClientCredentialCorePair(requirement: .required)
    let selectionRequest = try suspendClientForExternalCredential(pair: &pair)
    let credential = try TLS13CredentialDescriptor(
      identifier: ascii("client-key-1").span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    let signingTransition = try pair.client.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signingTransition {
    case .suspended(.signature(let request)):
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected external capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("client signature did not suspend")
    }
    do {
      _ = try pair.client.resume(
        .signature(
          signatureRequest.token,
          OwnedBytes(copying: ContiguousArray(repeating: UInt8(0), count: 64).span)
        )
      )
      XCTFail("invalid external client signature was accepted")
    } catch let error {
      XCTAssertEqual(error, .certificateVerifyFailure)
    }
    XCTAssertFalse(pair.client.isEstablished)
  }

  func testPostHandshakeExternalClientCredentialAndTrustCapabilities() throws {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    var credentialPair = try makeExternalClientCredentialCorePair(
      requirement: .required,
      timing: .postHandshake
    )
    let credentialClientHello = try credentialPair.client.start()
    let credentialServerOutput = try credentialPair.server
      .receiveHandshakeMessage(credentialClientHello.bytes.span, at: .initial)
    try completeCoreHandshake(
      pair: &credentialPair,
      serverOutput: credentialServerOutput
    )
    let credentialContext: ContiguousArray<UInt8> = [0x31, 0x32]
    let credentialRequestOutput = try credentialPair.server
      .requestPostHandshakeClientAuthentication(
        requestContext: credentialContext.span
      )
    let credentialRequest = try emittedApplicationHandshakeBytes(
      credentialRequestOutput
    )
    let selectionTransition = try credentialPair.client
      .receivePostHandshakeAuthenticationRequestStep(credentialRequest.span)
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selectionTransition {
    case .suspended(.credentialSelection(let request)):
      selectionRequest = request
    case .suspended:
      return XCTFail("unexpected post-handshake capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("external post-handshake credential did not suspend")
    }
    let credential = try TLS13CredentialDescriptor(
      identifier: ascii("post-handshake-client-key").span,
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    let signatureTransition = try credentialPair.client.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request)):
      signatureRequest = request
    case .suspended:
      return XCTFail("unexpected post-handshake capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("external post-handshake signature did not suspend")
    }
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: signatureRequest.message.span)
    let credentialOutputTransition = try credentialPair.client.resume(
      .signature(
        signatureRequest.token,
        OwnedBytes(consuming: signature)
      )
    )
    let credentialFlight: OwnedBytes
    switch consume credentialOutputTransition {
    case .output(let output):
      credentialFlight = try emittedApplicationHandshakeBytes(output)
    case .suspended:
      return XCTFail("accepted post-handshake signature suspended again")
    }
    for message in try TLS13HandshakeCodec.splitMessages(
      credentialFlight.span
    ) {
      _ = try credentialPair.server.receiveHandshakeMessage(
        message.span,
        at: .application
      )
    }
    XCTAssertNotNil(credentialPair.server.authenticatedClientIdentity)

    var trustPair = try makeExternalClientTrustCorePair(
      timing: .postHandshake
    )
    let trustClientHello = try trustPair.client.start()
    let trustServerOutput = try trustPair.server.receiveHandshakeMessage(
      trustClientHello.bytes.span,
      at: .initial
    )
    try completeCoreHandshake(pair: &trustPair, serverOutput: trustServerOutput)
    let trustContext: ContiguousArray<UInt8> = [0x41, 0x42]
    let trustRequestOutput = try trustPair.server
      .requestPostHandshakeClientAuthentication(
        requestContext: trustContext.span
      )
    let trustRequestMessage = try emittedApplicationHandshakeBytes(
      trustRequestOutput
    )
    let localClientTransition = try trustPair.client
      .receivePostHandshakeAuthenticationRequestStep(trustRequestMessage.span)
    let localClientOutput: TLS13HandshakeCoreOutput
    switch consume localClientTransition {
    case .output(let output):
      localClientOutput = output
    case .suspended:
      return XCTFail("local post-handshake identity unexpectedly suspended")
    }
    let trustFlight = try emittedApplicationHandshakeBytes(localClientOutput)
    let trustMessages = try TLS13HandshakeCodec.splitMessages(trustFlight.span)
    let trustCertificateMessage = trustMessages[0]
    let trustTransition = try trustPair.server.receiveHandshakeMessageStep(
      trustCertificateMessage.span,
      at: .application
    )
    let trustRequest: TLS13PeerTrustEvaluationRequest
    switch consume trustTransition {
    case .suspended(.peerTrustEvaluation(let request)):
      trustRequest = request
    case .suspended:
      return XCTFail("unexpected post-handshake capability request")
    case .output(let output):
      _ = output.remainingEffectCount
      return XCTFail("external post-handshake trust did not suspend")
    }
    let trustResume = try trustPair.server.resume(
      .peerTrustAccepted(trustRequest.token)
    )
    switch consume trustResume {
    case .output(let output):
      XCTAssertEqual(output.remainingEffectCount, 0)
    case .suspended:
      return XCTFail("accepted post-handshake trust suspended again")
    }
    var trustMessageIndex = 0
    for message in trustMessages {
      if trustMessageIndex > 0 {
        _ = try trustPair.server.receiveHandshakeMessage(
          message.span,
          at: .application
        )
      }
      trustMessageIndex += 1
    }
    XCTAssertNotNil(trustPair.server.authenticatedClientIdentity)
  }

  private struct SecretSnapshot: Equatable {
    let client: ContiguousArray<UInt8>
    let server: ContiguousArray<UInt8>
  }

  private struct CorePair: ~Copyable {
    var client: TLS13ClientHandshakeCore
    var server: TLS13ServerHandshakeCore
  }

  private func makeECHCorePair(
    serverConfigurationMatches: Bool
  ) throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientConfigScalar = ContiguousArray(repeating: UInt8(0x41), count: 32)
    let clientConfigKey = try X25519PrivateKey(bytes: clientConfigScalar.span)
    let clientConfig = try ECHConfig(
      configID: 17,
      publicKey: clientConfigKey.publicKey().span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 64,
      publicName: ascii("public.example").span
    )
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [clientConfig])
    )
    let clientECH = try ECHClientConfiguration(
      selectedConfiguration: selected,
      outerRandom: ContiguousArray(repeating: UInt8(0xA1), count: 32).span,
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x80))
    )

    let serverConfigScalar = ContiguousArray(
      repeating: serverConfigurationMatches ? UInt8(0x41) : UInt8(0x42),
      count: 32
    )
    let serverConfigPublicKey = try X25519PrivateKey(
      bytes: serverConfigScalar.span
    ).publicKey()
    let serverConfig = try ECHConfig(
      configID: serverConfigurationMatches ? 17 : 18,
      publicKey: serverConfigPublicKey.span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 64,
      publicName: ascii("public.example").span
    )
    let serverECH = try ECHServerConfiguration(
      config: serverConfig,
      privateKey: X25519PrivateKey(bytes: serverConfigScalar.span)
    )
    let serverECHConfigurations = try ECHServerConfigurationSet(
      configurations: [serverECH]
    )
    let certificate = try deterministicCertificate(
      dnsNames: ["origin.example", "public.example"]
    )
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      serverName: ascii("origin.example").span,
      verificationInstant: instant,
      echConfiguration: clientECH
    )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificate.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      echConfigurations: serverECHConfigurations
    )
    return CorePair(client: client, server: server)
  }

  private func makeECHResumptionCorePair() throws -> CorePair {
    let issuedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let receivedAt = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_001,
      nanoseconds: 0
    )
    let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
    let nonce = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
    let master = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    var serverState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7
    )
    let serverPSK = try serverState.consumePSK()
    let clientState = try TLS13ResumptionState(
      ticket: ticket.span,
      ticketNonce: nonce.span,
      resumptionMasterSecret: master.span,
      cipherSuite: .aes128GCM_SHA256,
      issuedAt: issuedAt,
      lifetime: 3_600,
      ageAdd: 7
    )

    let configScalar = ContiguousArray(repeating: UInt8(0x41), count: 32)
    let configKey = try X25519PrivateKey(bytes: configScalar.span)
    let config = try ECHConfig(
      configID: 17,
      publicKey: configKey.publicKey().span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 64,
      publicName: ascii("public.example").span
    )
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(
      from: ECHConfigList(configurations: [config])
    )
    let clientECH = try ECHClientConfiguration(
      selectedConfiguration: selected,
      outerRandom: ContiguousArray(repeating: UInt8(0xA1), count: 32).span,
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x80))
    )
    let serverECH = try ECHServerConfiguration(
      config: config,
      privateKey: X25519PrivateKey(bytes: configScalar.span)
    )
    let serverECHConfigurations = try ECHServerConfigurationSet(
      configurations: [serverECH]
    )
    let certificate = try deterministicCertificate(
      dnsNames: ["origin.example", "public.example"]
    )
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificate
      ),
      serverName: ascii("origin.example").span,
      verificationInstant: receivedAt,
      resumptionState: clientState,
      echConfiguration: clientECH
    )
    let server = try serverPSK.withBorrowedBytes { psk in
      try TLS13ServerHandshakeCore(
        random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
        ),
        certificateDER: certificate.span,
        signingKey: TLS13SigningKey(
          ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        ),
        verificationInstant: receivedAt,
        resumptionIdentity: ticket.span,
        resumptionPSK: psk,
        resumptionIssuedAt: issuedAt,
        resumptionLifetime: 3_600,
        resumptionAgeAdd: 7,
        echConfigurations: serverECHConfigurations
      )
    }
    return CorePair(client: client, server: server)
  }

  private func splitServerOutput(
    _ output: borrowing TLS13HandshakeCoreOutput
  ) throws -> (serverHello: OwnedBytes, encryptedFlight: OwnedBytes) {
    guard output.actions.count == 4,
      case .emitHandshakeBytes(.initial, let helloRange) = output.actions[0],
      case .emitHandshakeBytes(.handshake, let flightRange) = output.actions[2]
    else {
      throw TLS13HandshakeEngineError.malformedInput
    }
    return (
      OwnedBytes(copying: try output.bytes.span(in: helloRange)),
      OwnedBytes(copying: try output.bytes.span(in: flightRange))
    )
  }

  private func completeCoreHandshake(
    pair: inout CorePair,
    serverOutput: borrowing TLS13HandshakeCoreOutput
  ) throws {
    let clientFlight = try makeClientFinalFlight(
      pair: &pair,
      serverOutput: serverOutput
    )
    for message in try TLS13HandshakeCodec.splitMessages(clientFlight.span) {
      _ = try pair.server.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    XCTAssertTrue(pair.client.isEstablished)
    XCTAssertTrue(pair.server.isEstablished)
  }

  private func makeClientFinalFlight(
    pair: inout CorePair,
    serverOutput: borrowing TLS13HandshakeCoreOutput
  ) throws -> OwnedBytes {
    let flight = try splitServerOutput(serverOutput)
    _ = try pair.client.receiveHandshakeMessage(
      flight.serverHello.span,
      at: .initial
    )
    var clientFinished: OwnedBytes?
    for message in try TLS13HandshakeCodec.splitMessages(
      flight.encryptedFlight.span
    ) {
      let output = try pair.client.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
      for action in output.actions {
        if case .emitHandshakeBytes(.handshake, let range) = action {
          clientFinished = OwnedBytes(
            copying: try output.bytes.span(in: range)
          )
        }
      }
    }
    guard let clientFinished else {
      XCTFail("missing client final flight")
      throw TLS13HandshakeEngineError.malformedInput
    }
    return clientFinished
  }

  private func suspendClientForExternalCredential(
    pair: inout CorePair
  ) throws -> TLS13CredentialSelectionRequest {
    let clientHello = try pair.client.start()
    let serverOutput = try pair.server.receiveHandshakeMessage(
      clientHello.bytes.span,
      at: .initial
    )
    let flight = try splitServerOutput(serverOutput)
    _ = try pair.client.receiveHandshakeMessage(
      flight.serverHello.span,
      at: .initial
    )
    for message in try TLS13HandshakeCodec.splitMessages(
      flight.encryptedFlight.span
    ) {
      if message[0] == TLS13HandshakeCodec.finishedType {
        let transition = try pair.client.receiveHandshakeMessageStep(
          message.span,
          at: .handshake
        )
        switch consume transition {
        case .suspended(.credentialSelection(let request)):
          return request
        case .suspended:
          XCTFail("unexpected external capability request")
          throw TLS13HandshakeEngineError.invalidState
        case .output(let output):
          _ = output.remainingEffectCount
          XCTFail("client credential selection did not suspend")
          throw TLS13HandshakeEngineError.invalidState
        }
      }
      _ = try pair.client.receiveHandshakeMessage(
        message.span,
        at: .handshake
      )
    }
    XCTFail("missing server Finished")
    throw TLS13HandshakeEngineError.malformedInput
  }

  private func emittedHandshakeBytes(
    _ output: borrowing TLS13HandshakeCoreOutput
  ) throws -> OwnedBytes {
    for action in output.actions {
      if case .emitHandshakeBytes(.handshake, let range) = action {
        return OwnedBytes(copying: try output.bytes.span(in: range))
      }
    }
    XCTFail("missing handshake emission")
    throw TLS13HandshakeEngineError.invalidState
  }

  private func makeCorePair() throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    let serverKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span
    )
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let certificateDER = deterministicCertificate()
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientKey,
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: instant
    )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: serverKey,
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: instant
    )
    return CorePair(client: client, server: server)
  }

  private func makeClientAuthenticationCorePair(
    requirement: TLS13ClientCertificateRequirement,
    includeClientIdentity: Bool,
    timing: TLS13ClientAuthenticationTiming = .mainHandshake
  ) throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let certificateEntry = try TLS13CertificateEntry(
      certificateDER: certificateDER.span
    )
    let client: TLS13ClientHandshakeCore
    if includeClientIdentity {
      let identity = try TLS13ClientIdentity(
        certificateEntries: [certificateEntry],
        signingKey: TLS13SigningKey(
          ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
        ),
        verificationInstant: instant
      )
      client = try TLS13ClientHandshakeCore(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        ),
        certificateValidator: try makeCertificateValidator(
          certificateDER: certificateDER
        ),
        clientIdentity: identity,
        verificationInstant: instant
      )
    } else {
      client = try TLS13ClientHandshakeCore(
        random: ContiguousArray(repeating: 0x01, count: 32).span,
        ephemeralKey: X25519PrivateKey(
          bytes: ContiguousArray(repeating: 0x11, count: 32).span
        ),
        certificateValidator: try makeCertificateValidator(
          certificateDER: certificateDER
        ),
        verificationInstant: instant
      )
    }
    let clientCertificateValidator =
      try RFC5280TLS13ClientCertificateValidator(
        trustAnchors: [certificate]
      )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: requirement,
        timing: timing,
        validator: clientCertificateValidator
      )
    )
    return CorePair(client: client, server: server)
  }

  private func emittedApplicationHandshakeBytes(
    _ output: borrowing TLS13HandshakeCoreOutput
  ) throws -> OwnedBytes {
    for action in output.actions {
      if case .emitHandshakeBytes(.application, let range) = action {
        return OwnedBytes(copying: try output.bytes.span(in: range))
      }
    }
    XCTFail("missing application-epoch handshake emission")
    throw TLS13HandshakeEngineError.invalidState
  }

  private func makeExternalClientTrustCorePair(
    timing: TLS13ClientAuthenticationTiming = .mainHandshake
  ) throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let certificateEntry = try TLS13CertificateEntry(
      certificateDER: certificateDER.span
    )
    let clientIdentity = try TLS13ClientIdentity(
      certificateEntries: [certificateEntry],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant
    )
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      clientIdentity: clientIdentity,
      verificationInstant: instant
    )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateEntries: [certificateEntry],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        externalTrust: TLS13ExternalClientTrust(requirement: .required),
        timing: timing
      )
    )
    return CorePair(client: client, server: server)
  }

  private func makeExternalClientCredentialCorePair(
    requirement: TLS13ClientCertificateRequirement,
    timing: TLS13ClientAuthenticationTiming = .mainHandshake
  ) throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let certificateDER = deterministicCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x01), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x11), count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      externalClientCredential: TLS13ExternalClientCredential(),
      verificationInstant: instant
    )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: UInt8(0x02), count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: UInt8(0x22), count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: requirement,
        timing: timing,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )
    return CorePair(client: client, server: server)
  }

  private func makeP256ClientAuthenticationCorePair() throws -> CorePair {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_750_000_000,
      nanoseconds: 0
    )
    let certificateDER = p256Certificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let certificateEntry = try TLS13CertificateEntry(
      certificateDER: certificateDER.span
    )
    var clientScalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    clientScalar[31] = 1
    let identity = try TLS13ClientIdentity(
      certificateEntries: [certificateEntry],
      signingKey: TLS13SigningKey(
        p256: try P256PrivateKey(bytes: clientScalar.span)
      ),
      verificationInstant: instant
    )
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      clientIdentity: identity,
      verificationInstant: instant
    )
    var serverScalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    serverScalar[31] = 1
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        p256: try P256PrivateKey(bytes: serverScalar.span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )
    return CorePair(client: client, server: server)
  }

  private func makeHybridCorePair() throws -> CorePair {
    let instant = try VerificationInstant(
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
    let client = try TLS13ClientHandshakeCore(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      keyExchange: clientKeyExchange,
      certificateValidator: try makeCertificateValidator(
        certificateDER: certificateDER
      ),
      verificationInstant: instant
    )
    let server = try TLS13ServerHandshakeCore(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      keyExchange: serverKeyExchange,
      keyExchangeEntropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x70)),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(ed25519: signingKey),
      verificationInstant: instant
    )
    return CorePair(client: client, server: server)
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

  private func copySecrets(
    _ secrets: consuming TLS13TrafficSecretPair
  ) -> SecretSnapshot {
    let client = secrets.withClientSecret { copy($0) }
    let server = secrets.withServerSecret { copy($0) }
    return SecretSnapshot(client: client, server: server)
  }

  private func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
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

  private func delegatedCredentialCertificate() throws -> ContiguousArray<UInt8> {
    var tbs = bytes(
      "308181a003020102020101300506032b65703000301e"
        + "170d3234303130313030303030305a"
        + "170d3235303130313030303030305a3000"
        + "302a300506032b6570032100"
    )
    tbs.append(contentsOf: deterministicServerPublicKey())
    tbs.append(contentsOf: bytes(
      "a320301e"
        + "300b0603551d0f040403020780"
        + "300f06092b0601040182da4b2c04020500"
    ))
    let signer = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try signer.sign(message: tbs.span)
    var certificate = ContiguousArray<UInt8>([0x30, 0x81, 0xCE])
    certificate.append(contentsOf: tbs)
    certificate.append(contentsOf: bytes("300506032b6570034100"))
    certificate.append(contentsOf: signature)
    return certificate
  }

  private func ed25519SubjectPublicKeyInfo(
    publicKey: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result: ContiguousArray<UInt8> = [
      0x30, 0x2A,
      0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
      0x03, 0x21, 0x00,
    ]
    result.append(contentsOf: publicKey)
    return result
  }

  private func p256Certificate() -> ContiguousArray<UInt8> {
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

  private func emittedDatagrams(
    _ batch: DTLSActionBatch
  ) throws -> ContiguousArray<OwnedBytes> {
    var datagrams = ContiguousArray<OwnedBytes>()
    for action in batch.actions {
      if case .emitDatagram(let range) = action {
        datagrams.append(OwnedBytes(copying: try batch.bytes.span(in: range)))
      }
    }
    return datagrams
  }

  private func deliveredApplicationData(
    _ batch: DTLSActionBatch
  ) throws -> ContiguousArray<UInt8> {
    for action in batch.actions {
      if case .deliverApplicationData(let range, let isEarlyData) = action {
        XCTAssertFalse(isEarlyData)
        return copy(try batch.bytes.span(in: range))
      }
    }
    throw DTLS13ConnectionError.malformedDatagram
  }

  private func makeCertificateValidator(
    certificateDER: ContiguousArray<UInt8>
  ) throws -> RFC5280TLS13ServerCertificateValidator {
    try RFC5280TLS13ServerCertificateValidator(
      trustAnchors: [try X509Certificate(der: certificateDER.span)]
    )
  }

  private func deterministicCertificate(
    dnsNames: [String]
  ) throws -> ContiguousArray<UInt8> {
    var body = ContiguousArray<UInt8>()
    body.append(contentsOf: [0xA0, 0x03, 0x02, 0x01, 0x02])
    body.append(contentsOf: [0x02, 0x01, 0x01])
    body.append(contentsOf: [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])
    body.append(contentsOf: [0x30, 0x00])
    body.append(contentsOf: [0x30, 0x1E, 0x17, 0x0D])
    body.append(contentsOf: ContiguousArray("240101000000Z".utf8))
    body.append(contentsOf: [0x17, 0x0D])
    body.append(contentsOf: ContiguousArray("250101000000Z".utf8))
    body.append(contentsOf: [0x30, 0x00])
    body.append(contentsOf: [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])
    body.append(contentsOf: [0x03, 0x21, 0x00])
    body.append(contentsOf: deterministicServerPublicKey())

    var generalNames = ContiguousArray<UInt8>()
    for name in dnsNames {
      let encoded = ascii(name)
      XCTAssertLessThan(encoded.count, 128)
      generalNames.append(0x82)
      generalNames.append(UInt8(encoded.count))
      generalNames.append(contentsOf: encoded)
    }
    let namesSequence = derWrapped(tag: 0x30, body: generalNames)
    var extensionBody: ContiguousArray<UInt8> = [
      0x06, 0x03, 0x55, 0x1D, 0x11,
    ]
    extensionBody.append(contentsOf: derWrapped(tag: 0x04, body: namesSequence))
    let extensionValue = derWrapped(tag: 0x30, body: extensionBody)
    let extensions = derWrapped(tag: 0x30, body: extensionValue)
    body.append(contentsOf: derWrapped(tag: 0xA3, body: extensions))

    let tbs = derWrapped(tag: 0x30, body: body)
    let key = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let signature = try Ed25519.sign(message: tbs.span, using: key)
    var certificateBody = tbs
    certificateBody.append(contentsOf: [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])
    var signatureBody: ContiguousArray<UInt8> = [0x00]
    signatureBody.append(contentsOf: signature)
    certificateBody.append(contentsOf: derWrapped(tag: 0x03, body: signatureBody))
    return derWrapped(tag: 0x30, body: certificateBody)
  }

  private func derWrapped(
    tag: UInt8,
    body: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result: ContiguousArray<UInt8> = [tag]
    if body.count < 128 {
      result.append(UInt8(body.count))
    } else {
      result.append(0x81)
      result.append(UInt8(body.count))
    }
    result.append(contentsOf: body)
    return result
  }

  private func ascii(_ value: String) -> ContiguousArray<UInt8> {
    ContiguousArray(value.utf8)
  }
}

private struct CoreAcceptingEarlyDataReplayProtector:
  TLS13EarlyDataReplayProtecting
{
  func evaluate(
    _ context: TLS13EarlyDataReplayContext
  ) throws -> TLS13EarlyDataReplayDecision {
    _ = context
    return .accept
  }
}
