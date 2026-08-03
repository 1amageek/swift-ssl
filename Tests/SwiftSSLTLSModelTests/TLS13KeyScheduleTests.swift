import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import XCTest

final class TLS13KeyScheduleTests: XCTestCase {
  func testRFC8448SimpleHandshakeKnownAnswers() throws {
    let zeroPSK = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let sharedSecret = bytes(
      "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    )
    let helloTranscriptHash = bytes(
      "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    )
    let applicationTranscriptHash = bytes(
      "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    )
    let completedTranscriptHash = bytes(
      "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"
    )

    let schedule = try TLS13KeySchedule(
      cipherSuite: .aes128GCM_SHA256,
      preSharedKey: zeroPSK.span
    )
    let handshake = try schedule.makeHandshakeSecrets(
      ecdheSharedSecret: sharedSecret.span,
      transcriptHash: helloTranscriptHash.span
    )

    try handshake.withClientTrafficSecret { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
      )
    }
    try handshake.withServerTrafficSecret { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
      )
    }
    let clientFinished = try handshake.makeClientFinishedVerifyData(
      transcriptHash: applicationTranscriptHash.span
    )
    XCTAssertEqual(
      copy(clientFinished.span),
      bytes("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
    )

    let application = try handshake.makeApplicationSecrets(
      transcriptHash: applicationTranscriptHash.span
    )
    try application.withClientTrafficSecret { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
      )
    }
    try application.withServerTrafficSecret { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
      )
    }
    try application.withExporterMasterSecret { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
      )
    }
    let exported = try application.exportKeyingMaterial(
      label: "EXTRACTOR-dtls_srtp",
      context: Span<UInt8>(),
      outputByteCount: 88
    )
    exported.withBorrowedBytes { secret in
      XCTAssertEqual(
        copy(secret),
        bytes(
          "0e30a85a5b29a641bc75ca72910008b1b8236c3247fd404f89f347b815ce576c"
            + "9afeb1dde16f00090819e0fe58fd49bee1f1a36de5bd6250e1ab4f04d612819d"
            + "07ac0a605c3066e12c13cdc36002fdcce168b7fc660c5ef9"
        )
      )
    }

    let resumption = try handshake.makeResumptionMasterSecret(
      transcriptHash: completedTranscriptHash.span
    )
    try resumption.withBorrowedBytes { secret in
      XCTAssertEqual(
        copy(secret),
        bytes("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")
      )
    }
  }

  func testDerivesHandshakeAndApplicationTrafficSecrets() throws {
    let emptyPSK = ContiguousArray<UInt8>()
    let ecdhe = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
    let transcript = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
    var schedule = try TLS13KeySchedule(
      cipherSuite: .aes128GCM_SHA256,
      preSharedKey: emptyPSK.span
    )
    let handshake = try schedule.makeHandshakeSecrets(
      ecdheSharedSecret: ecdhe.span,
      transcriptHash: transcript.span
    )
    var clientSecret = ContiguousArray<UInt8>()
    try handshake.withClientTrafficSecret { secret in
      clientSecret = copy(secret)
    }
    XCTAssertEqual(clientSecret.count, 32)
    XCTAssertNotEqual(Set(clientSecret), [0])

    let serverFinished = try handshake.makeServerFinishedVerifyData(
      transcriptHash: transcript.span
    )
    XCTAssertEqual(serverFinished.count, 32)
    XCTAssertNotEqual(copy(serverFinished.span), clientSecret)

    let application = try handshake.makeApplicationSecrets(transcriptHash: transcript.span)
    var applicationSecret = ContiguousArray<UInt8>()
    try application.withServerTrafficSecret { secret in
      applicationSecret = copy(secret)
    }
    XCTAssertEqual(applicationSecret.count, 32)
    XCTAssertNotEqual(applicationSecret, clientSecret)
  }

  func testSHA384SuiteAndInputFailures() throws {
    let psk = ContiguousArray<UInt8>(repeating: 0x55, count: 48)
    let ecdhe = ContiguousArray<UInt8>(repeating: 0x66, count: X25519SharedSecret.byteCount)
    let transcript = ContiguousArray<UInt8>(repeating: 0x77, count: 48)
    let schedule = try TLS13KeySchedule(
      cipherSuite: .aes256GCM_SHA384,
      preSharedKey: psk.span
    )
    let handshake = try schedule.makeHandshakeSecrets(
      ecdheSharedSecret: ecdhe.span,
      transcriptHash: transcript.span
    )
    try handshake.withServerTrafficSecret { secret in
      XCTAssertEqual(secret.count, 48)
    }

    let invalidECDHE = ContiguousArray<UInt8>(repeating: 0, count: 48)
    do {
      _ = try schedule.makeHandshakeSecrets(
        ecdheSharedSecret: invalidECDHE.span,
        transcriptHash: transcript.span
      )
      XCTFail("invalid ECDHE length was accepted")
    } catch {
      XCTAssertEqual(error as? TLS13KeyScheduleError, .invalidECDHESecretLength(actual: 48))
    }
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
}
