import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import SwiftSSLX509
import XCTest

final class TLS13DelegatedCredentialTests: XCTestCase {
  func testRFC9345WireRoundTripsAcrossAdvertiseAndCertificateMessages() throws {
    let delegatedCredential = try TLS13DelegatedCredential(
      validTime: 86_400,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: ContiguousArray(repeating: 0x44, count: 32)
      ).span,
      delegationAlgorithm: .ed25519,
      signature: ContiguousArray(repeating: 0xA5, count: 64).span
    )
    let codec = RFC9345TLS13DelegatedCredentialCodec()
    let encoded = try codec.encode(delegatedCredential)
    XCTAssertEqual(try codec.decode(encoded.span), delegatedCredential)

    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x02, count: 32).span,
      delegatedCredentialAlgorithms: [.ed25519, .ecdsaP256SHA256]
    )
    XCTAssertEqual(
      try TLS13HandshakeCodec.parseClientHello(clientHello.span)
        .delegatedCredentialAlgorithms,
      [.ed25519, .ecdsaP256SHA256]
    )

    let certificateRequest = try TLS13HandshakeCodec.makeCertificateRequest(
      signatureSchemes: [.ed25519],
      delegatedCredentialAlgorithms: [.ed25519]
    )
    XCTAssertEqual(
      try TLS13HandshakeCodec.parseCertificateRequest(certificateRequest.span)
        .delegatedCredentialAlgorithms,
      [.ed25519]
    )

    let entry = try TLS13CertificateEntry(
      certificateDER: ContiguousArray<UInt8>([0x01]).span,
      delegatedCredential: delegatedCredential
    )
    let certificateMessage = try TLS13HandshakeCodec.makeCertificate(
      entries: [entry]
    )
    let parsed = try TLS13HandshakeCodec.parseCertificateMessage(
      certificateMessage.span
    )
    XCTAssertEqual(
      parsed.entries.first?.delegatedCredential,
      delegatedCredential
    )
  }

  func testStreamHandshakeAuthenticatesWithDelegatedKey() throws {
    let certificateDER = try delegatedCredentialCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_704_153_600,
      nanoseconds: 0
    )
    let certificateSigningKey = TLS13SigningKey(
      ed25519: try Ed25519PrivateKey(seed: certificateSeed().span)
    )
    let delegatedPrivateKey = try Ed25519PrivateKey(
      seed: delegatedSeed().span
    )
    let delegatedPublicKey = try delegatedPrivateKey.publicKey()
    let delegatedPublicKeyInfo = ed25519SubjectPublicKeyInfo(
      publicKey: delegatedPublicKey
    )
    let delegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: delegatedPublicKeyInfo.span,
      certificate: certificate,
      role: .server,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let certificateEntry = try TLS13CertificateEntry(
      certificateDER: certificateDER.span,
      delegatedCredential: delegatedCredential
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try RFC5280TLS13ServerCertificateValidator(
        trustAnchors: [certificate]
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateEntries: [certificateEntry],
      signingKey: TLS13SigningKey(ed25519: delegatedPrivateKey),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testRequiredClientAuthenticationUsesDelegatedKeysInBothDirections()
    throws
  {
    let certificateDER = try delegatedCredentialCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_704_153_600,
      nanoseconds: 0
    )
    let certificateSigningKey = TLS13SigningKey(
      ed25519: try Ed25519PrivateKey(seed: certificateSeed().span)
    )
    let serverPrivateKey = try Ed25519PrivateKey(
      seed: delegatedSeed().span
    )
    let serverPublicKey = try serverPrivateKey.publicKey()
    let serverDelegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: serverPublicKey
      ).span,
      certificate: certificate,
      role: .server,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let clientPrivateKey = try Ed25519PrivateKey(
      seed: clientDelegatedSeed().span
    )
    let clientPublicKey = try clientPrivateKey.publicKey()
    let clientDelegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: clientPublicKey
      ).span,
      certificate: certificate,
      role: .client,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let clientIdentity = try TLS13ClientIdentity(
      certificateEntries: [
        try TLS13CertificateEntry(
          certificateDER: certificateDER.span,
          delegatedCredential: clientDelegatedCredential
        )
      ],
      signingKey: TLS13SigningKey(ed25519: clientPrivateKey),
      verificationInstant: instant
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try RFC5280TLS13ServerCertificateValidator(
        trustAnchors: [certificate]
      ),
      clientIdentity: clientIdentity,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateEntries: [
        try TLS13CertificateEntry(
          certificateDER: certificateDER.span,
          delegatedCredential: serverDelegatedCredential
        )
      ],
      signingKey: TLS13SigningKey(ed25519: serverPrivateKey),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
    XCTAssertNotNil(server.authenticatedClientIdentity)
  }

  func testExternalServerCredentialSignsWithDelegatedKey() throws {
    let certificateDER = try delegatedCredentialCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_704_153_600,
      nanoseconds: 0
    )
    let certificateSigningKey = TLS13SigningKey(
      ed25519: try Ed25519PrivateKey(seed: certificateSeed().span)
    )
    let delegatedPrivateKey = try Ed25519PrivateKey(
      seed: delegatedSeed().span
    )
    let delegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: ed25519SubjectPublicKeyInfo(
        publicKey: try delegatedPrivateKey.publicKey()
      ).span,
      certificate: certificate,
      role: .server,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let credential = try TLS13CredentialDescriptor(
      identifier: ContiguousArray("delegated-server".utf8).span,
      certificateEntries: [
        try TLS13CertificateEntry(
          certificateDER: certificateDER.span,
          delegatedCredential: delegatedCredential
        )
      ],
      signatureScheme: .ed25519,
      verificationInstant: instant
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try RFC5280TLS13ServerCertificateValidator(
        trustAnchors: [certificate]
      ),
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      externalServerCredential: TLS13ExternalServerCredential(),
      verificationInstant: instant
    )

    let clientHello = try client.start()
    let selection = try server.receiveRecordStep(clientHello.bytes.span)
    let selectionRequest: TLS13CredentialSelectionRequest
    switch consume selection {
    case .suspended(.credentialSelection(let request), _):
      selectionRequest = request
    default:
      return XCTFail("credential selection did not suspend")
    }
    XCTAssertEqual(selectionRequest.delegatedCredentialAlgorithms, [
      .ecdsaP256SHA256, .ed25519,
    ])
    let signatureTransition = try server.resume(
      .credentialSelected(selectionRequest.token, credential)
    )
    let signatureRequest: TLS13SignatureRequest
    switch consume signatureTransition {
    case .suspended(.signature(let request), _):
      signatureRequest = request
    default:
      return XCTFail("delegated signature did not suspend")
    }
    let signature = try delegatedPrivateKey.sign(
      message: signatureRequest.message.span
    )
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
      return XCTFail("delegated signature suspended twice")
    }
    let clientFinished = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinished.bytes.span)

    XCTAssertTrue(client.isEstablished)
    XCTAssertTrue(server.isEstablished)
  }

  func testValidatorRejectsWrongRoleTamperingAndExcessLifetime() throws {
    let certificateDER = try delegatedCredentialCertificate()
    let certificate = try X509Certificate(der: certificateDER.span)
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_704_153_600,
      nanoseconds: 0
    )
    let certificateSigningKey = TLS13SigningKey(
      ed25519: try Ed25519PrivateKey(seed: certificateSeed().span)
    )
    let delegatedPrivateKey = try Ed25519PrivateKey(
      seed: delegatedSeed().span
    )
    let delegatedPublicKeyInfo = ed25519SubjectPublicKeyInfo(
      publicKey: try delegatedPrivateKey.publicKey()
    )
    let delegatedCredential = try TLS13DelegatedCredential.issue(
      validTime: 3 * 24 * 60 * 60,
      certificateVerifyAlgorithm: .ed25519,
      subjectPublicKeyInfoDER: delegatedPublicKeyInfo.span,
      certificate: certificate,
      role: .server,
      certificateSigningKey: certificateSigningKey,
      at: instant
    )
    let validator = RFC9345TLS13DelegatedCredentialValidator()
    XCTAssertThrowsError(
      try validator.validate(
        delegatedCredential,
        certificate: certificate,
        role: .client,
        signatureSchemes: [.ed25519],
        delegatedCredentialAlgorithms: [.ed25519],
        at: instant
      )
    ) { error in
      XCTAssertEqual(
        error as? TLS13DelegatedCredentialError,
        .invalidDelegationSignature
      )
    }

    var tamperedSignature = ContiguousArray<UInt8>()
    delegatedCredential.signature.withBorrowedBytes {
      var index = 0
      while index < $0.count {
        tamperedSignature.append($0[index])
        index += 1
      }
    }
    tamperedSignature[0] ^= 0x80
    let tampered = try TLS13DelegatedCredential(
      validTime: delegatedCredential.validTime,
      certificateVerifyAlgorithm:
        delegatedCredential.certificateVerifyAlgorithm,
      subjectPublicKeyInfoDER: delegatedPublicKeyInfo.span,
      delegationAlgorithm: delegatedCredential.delegationAlgorithm,
      signature: tamperedSignature.span
    )
    XCTAssertThrowsError(
      try validator.validate(
        tampered,
        certificate: certificate,
        role: .server,
        signatureSchemes: [.ed25519],
        delegatedCredentialAlgorithms: [.ed25519],
        at: instant
      )
    ) { error in
      XCTAssertEqual(
        error as? TLS13DelegatedCredentialError,
        .invalidDelegationSignature
      )
    }

    XCTAssertThrowsError(
      try TLS13DelegatedCredential.issue(
        validTime: 10 * 24 * 60 * 60,
        certificateVerifyAlgorithm: .ed25519,
        subjectPublicKeyInfoDER: delegatedPublicKeyInfo.span,
        certificate: certificate,
        role: .server,
        certificateSigningKey: certificateSigningKey,
        at: instant
      )
    ) { error in
      XCTAssertEqual(
        error as? TLS13DelegatedCredentialError,
        .credentialLifetimeExceeded
      )
    }
  }

  private func delegatedCredentialCertificate() throws -> ContiguousArray<UInt8> {
    var tbs = bytes(
      "308181a003020102020101300506032b65703000301e"
        + "170d3234303130313030303030305a"
        + "170d3235303130313030303030305a3000"
        + "302a300506032b6570032100"
    )
    tbs.append(contentsOf: certificatePublicKey())
    tbs.append(contentsOf: bytes(
      "a320301e"
        + "300b0603551d0f040403020780"
        + "300f06092b0601040182da4b2c04020500"
    ))
    let signer = try Ed25519PrivateKey(seed: certificateSeed().span)
    let signature = try signer.sign(message: tbs.span)
    var certificate = ContiguousArray<UInt8>([0x30, 0x81, 0xCE])
    certificate.append(contentsOf: tbs)
    certificate.append(contentsOf: bytes("300506032b6570034100"))
    certificate.append(contentsOf: signature)
    return certificate
  }

  private func certificateSeed() -> ContiguousArray<UInt8> {
    bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  }

  private func delegatedSeed() -> ContiguousArray<UInt8> {
    ContiguousArray(repeating: 0x42, count: 32)
  }

  private func clientDelegatedSeed() -> ContiguousArray<UInt8> {
    ContiguousArray(repeating: 0x43, count: 32)
  }

  private func certificatePublicKey() -> ContiguousArray<UInt8> {
    bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
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
}
