import SSLCore
import SSLX509

public struct RFC9345TLS13DelegatedCredentialCodec:
  TLS13DelegatedCredentialCoding,
  Sendable
{
  public init() {}

  public func encode(
    _ delegatedCredential: TLS13DelegatedCredential
  ) throws(TLS13DelegatedCredentialError) -> OwnedBytes {
    let credential = try encodeCredential(
      validTime: delegatedCredential.validTime,
      certificateVerifyAlgorithm:
        delegatedCredential.certificateVerifyAlgorithm,
      subjectPublicKeyInfo: delegatedCredential.subjectPublicKeyInfo
    )
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(credential.count + delegatedCredential.signature.count + 4)
    append(credential.span, to: &output)
    appendUInt16(delegatedCredential.delegationAlgorithm.rawValue, to: &output)
    appendUInt16(UInt16(delegatedCredential.signature.count), to: &output)
    append(delegatedCredential.signature.span, to: &output)
    return OwnedBytes(consuming: output)
  }

  public func decode(
    _ encoded: Span<UInt8>
  ) throws(TLS13DelegatedCredentialError) -> TLS13DelegatedCredential {
    var cursor = ByteCursor(encoded)
    do {
      let validTime = try cursor.readUInt32BigEndian()
      guard let certificateVerifyAlgorithm = TLS13SignatureScheme(
        rawValue: try cursor.readUInt16BigEndian()
      ) else {
        throw TLS13DelegatedCredentialError.unsupportedCertificateVerifyAlgorithm
      }
      let publicKeyByteCount = Int(try cursor.readUInt24BigEndian())
      guard publicKeyByteCount > 0 else {
        throw TLS13DelegatedCredentialError.malformedCredential
      }
      let publicKey = try cursor.readSpan(count: publicKeyByteCount)
      guard let delegationAlgorithm = TLS13SignatureScheme(
        rawValue: try cursor.readUInt16BigEndian()
      ) else {
        throw TLS13DelegatedCredentialError.unsupportedDelegationAlgorithm
      }
      let signatureByteCount = Int(try cursor.readUInt16BigEndian())
      guard signatureByteCount > 0 else {
        throw TLS13DelegatedCredentialError.malformedCredential
      }
      let signature = try cursor.readSpan(count: signatureByteCount)
      try cursor.requireFullyConsumed()
      return try TLS13DelegatedCredential(
        validTime: validTime,
        certificateVerifyAlgorithm: certificateVerifyAlgorithm,
        subjectPublicKeyInfoDER: publicKey,
        delegationAlgorithm: delegationAlgorithm,
        signature: signature
      )
    } catch let error as TLS13DelegatedCredentialError {
      throw error
    } catch {
      throw .malformedCredential
    }
  }

  public func makeSigningInput(
    validTime: UInt32,
    certificateVerifyAlgorithm: TLS13SignatureScheme,
    subjectPublicKeyInfoDER: Span<UInt8>,
    delegationAlgorithm: TLS13SignatureScheme,
    role: TLSRole,
    certificateDER: Span<UInt8>
  ) throws(TLS13DelegatedCredentialError) -> OwnedBytes {
    let subjectPublicKeyInfo: SubjectPublicKeyInfo
    do {
      subjectPublicKeyInfo = try SubjectPublicKeyInfo(der: subjectPublicKeyInfoDER)
    } catch let error {
      throw .subjectPublicKeyInfo(error)
    }
    guard certificateVerifyAlgorithm == .ecdsaP256SHA256
      || certificateVerifyAlgorithm == .ed25519,
      certificateVerifyAlgorithm.matches(subjectPublicKeyInfo),
      !subjectPublicKeyInfo.isRSA
    else {
      throw .unsupportedCertificateVerifyAlgorithm
    }
    let credential = try encodeCredential(
      validTime: validTime,
      certificateVerifyAlgorithm: certificateVerifyAlgorithm,
      subjectPublicKeyInfo: subjectPublicKeyInfo
    )
    let context: StaticString
    switch role {
    case .client:
      context = "TLS, client delegated credentials"
    case .server:
      context = "TLS, server delegated credentials"
    }
    let contextBytes = context.withUTF8Buffer { buffer in
      ContiguousArray(buffer)
    }
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(
      64 + contextBytes.count + 1 + certificateDER.count + credential.count + 2
    )
    output.append(contentsOf: repeatElement(0x20, count: 64))
    output.append(contentsOf: contextBytes)
    output.append(0)
    append(certificateDER, to: &output)
    append(credential.span, to: &output)
    appendUInt16(delegationAlgorithm.rawValue, to: &output)
    return OwnedBytes(consuming: output)
  }

  private func encodeCredential(
    validTime: UInt32,
    certificateVerifyAlgorithm: TLS13SignatureScheme,
    subjectPublicKeyInfo: SubjectPublicKeyInfo
  ) throws(TLS13DelegatedCredentialError) -> OwnedBytes {
    let publicKeyByteCount = subjectPublicKeyInfo.withDERBytes { $0.count }
    guard publicKeyByteCount > 0, publicKeyByteCount <= 0x00FF_FFFF else {
      throw .malformedCredential
    }
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(publicKeyByteCount + 9)
    output.append(UInt8(truncatingIfNeeded: validTime >> 24))
    output.append(UInt8(truncatingIfNeeded: validTime >> 16))
    output.append(UInt8(truncatingIfNeeded: validTime >> 8))
    output.append(UInt8(truncatingIfNeeded: validTime))
    appendUInt16(certificateVerifyAlgorithm.rawValue, to: &output)
    output.append(UInt8(truncatingIfNeeded: publicKeyByteCount >> 16))
    output.append(UInt8(truncatingIfNeeded: publicKeyByteCount >> 8))
    output.append(UInt8(truncatingIfNeeded: publicKeyByteCount))
    subjectPublicKeyInfo.withDERBytes { append($0, to: &output) }
    return OwnedBytes(consuming: output)
  }

  private func appendUInt16(
    _ value: UInt16,
    to output: inout ContiguousArray<UInt8>
  ) {
    output.append(UInt8(truncatingIfNeeded: value >> 8))
    output.append(UInt8(truncatingIfNeeded: value))
  }

  private func append(
    _ bytes: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < bytes.count {
      output.append(bytes[index])
      index += 1
    }
  }
}
import TLSTypes
