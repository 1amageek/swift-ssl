import SSLCore
import SSLASN1

@inline(__always)
private func copyProviderBytes(_ bytes: Span<UInt8>) -> [UInt8] {
  var result = [UInt8]()
  result.reserveCapacity(bytes.count)
  var index = 0
  while index < bytes.count {
    result.append(bytes[index])
    index += 1
  }
  return result
}

public struct DefaultProviderSHA256: ~Copyable, ProviderHashFunction {
  public static let digestByteCount = SHA256.digestByteCount
  private var context: SHA256Context

  public init() {
    context = SHA256Context()
  }

  public mutating func update(_ bytes: Span<UInt8>) {
    do {
      try context.update(bytes)
    } catch {
      preconditionFailure("SHA-256 provider exceeded the primitive input limit")
    }
  }

  public consuming func finalize() -> [UInt8] {
    var output = [UInt8](repeating: 0, count: Self.digestByteCount)
    do {
      var destination = output.mutableSpan
      try context.finalize(into: &destination)
    } catch {
      preconditionFailure("SHA-256 context rejected a fixed-size digest buffer")
    }
    return output
  }
}

public enum DefaultProviderHMACSHA256: ProviderMessageAuthenticationCode {
  public static let tagByteCount = HMACSHA256.tagByteCount

  public static func authenticate(
    _ message: Span<UInt8>,
    using key: Span<UInt8>
  ) -> [UInt8] {
    var output = [UInt8](repeating: 0, count: tagByteCount)
    do {
      var destination = output.mutableSpan
      try HMACSHA256.authenticate(message, using: key, into: &destination)
      return output
    } catch {
      preconditionFailure("HMAC-SHA-256 rejected a fixed-size output buffer")
    }
  }
}

public struct DefaultProviderChaCha20Poly1305: ProviderAuthenticatedCipher {
  public static let nonceByteCount = ChaCha20Poly1305.nonceByteCount
  public static let tagByteCount = ChaCha20Poly1305.tagByteCount

  private let key: [UInt8]

  public init(key: Span<UInt8>) throws(CryptoProviderError) {
    guard key.count == 32 else {
      throw .invalidLength(expected: 32, actual: key.count)
    }
    self.key = copyProviderBytes(key)
  }

  public func seal(
    _ plaintext: Span<UInt8>,
    nonce: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(CryptoProviderError) -> [UInt8] {
    var output = [UInt8](
      repeating: 0,
      count: plaintext.count + Self.tagByteCount
    )
    do {
      let cipher = try ChaCha20Poly1305(key: key.span)
      var destination = output.mutableSpan
      try cipher.seal(
        plaintext: plaintext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &destination
      )
      return output
    } catch let error {
      switch error {
      case .invalidKeyLength(_, let actual):
        throw .invalidLength(expected: 32, actual: actual)
      case .invalidNonceLength(let expected, let actual):
        throw .invalidLength(expected: expected, actual: actual)
      case .authenticationFailed:
        throw .authenticationFailure
      case .outputTooSmall, .overlappingInputAndOutput, .messageLimitReached:
        throw .primitiveFailure
      }
    }
  }

  public func open(
    _ ciphertextAndTag: Span<UInt8>,
    nonce: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(CryptoProviderError) -> [UInt8] {
    guard ciphertextAndTag.count >= Self.tagByteCount else {
      throw .invalidLength(
        expected: Self.tagByteCount,
        actual: ciphertextAndTag.count
      )
    }
    var output = [UInt8](
      repeating: 0,
      count: ciphertextAndTag.count - Self.tagByteCount
    )
    do {
      let cipher = try ChaCha20Poly1305(key: key.span)
      var destination = output.mutableSpan
      try cipher.open(
        ciphertextAndTag: ciphertextAndTag,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &destination
      )
      return output
    } catch let error {
      switch error {
      case .authenticationFailed:
        throw .authenticationFailure
      case .invalidNonceLength(let expected, let actual):
        throw .invalidLength(expected: expected, actual: actual)
      default:
        throw .primitiveFailure
      }
    }
  }
}

public enum DefaultProviderX25519: ProviderKeyAgreement {
  public struct PrivateKey: Sendable {
    fileprivate let bytes: [UInt8]
  }

  public struct PublicKey: Sendable {
    fileprivate let bytes: [UInt8]
  }

  public static func generatePrivateKey() throws(CryptoProviderError) -> PrivateKey {
    do {
      let key = try X25519PrivateKey.generate()
      return key.withBorrowedBytes { PrivateKey(bytes: copyProviderBytes($0)) }
    } catch {
      throw .entropyFailure
    }
  }

  public static func privateKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> PrivateKey {
    guard rawRepresentation.count == X25519PrivateKey.byteCount else {
      throw .invalidLength(
        expected: X25519PrivateKey.byteCount,
        actual: rawRepresentation.count
      )
    }
    do {
      _ = try X25519PrivateKey(bytes: rawRepresentation)
      return PrivateKey(bytes: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func publicKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> PublicKey {
    guard rawRepresentation.count == X25519PublicKey.byteCount else {
      throw .invalidLength(
        expected: X25519PublicKey.byteCount,
        actual: rawRepresentation.count
      )
    }
    do {
      _ = try X25519PublicKey(bytes: rawRepresentation)
      return PublicKey(bytes: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
    do {
      let key = try X25519PrivateKey(bytes: privateKey.bytes.span)
      return key.publicKey().withBorrowedBytes {
        PublicKey(bytes: copyProviderBytes($0))
      }
    } catch {
      preconditionFailure("validated X25519 private key could not be reconstructed")
    }
  }

  public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
    privateKey.bytes
  }

  public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
    publicKey.bytes
  }

  public static func sharedSecret(
    privateKey: PrivateKey,
    peerPublicKey: PublicKey
  ) throws(CryptoProviderError) -> [UInt8] {
    do {
      let privateKey = try X25519PrivateKey(bytes: privateKey.bytes.span)
      let publicKey = try X25519PublicKey(bytes: peerPublicKey.bytes.span)
      let secret = try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKey: publicKey
      )
      return secret.withBorrowedBytes { copyProviderBytes($0) }
    } catch {
      throw .keyAgreementFailure
    }
  }
}

public enum DefaultProviderEd25519: ProviderSignatureScheme {
  public struct SigningKey: Sendable {
    fileprivate let seed: [UInt8]
  }

  public struct VerifyingKey: Sendable {
    fileprivate let bytes: [UInt8]
  }

  public static func generateSigningKey() throws(CryptoProviderError) -> SigningKey {
    var seed = [UInt8](repeating: 0, count: Ed25519PrivateKey.seedByteCount)
    do {
      var destination = seed.mutableSpan
      try SystemRandom.fill(&destination)
      return SigningKey(seed: seed)
    } catch {
      throw .entropyFailure
    }
  }

  public static func signingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> SigningKey {
    do {
      _ = try Ed25519PrivateKey(seed: rawRepresentation)
      return SigningKey(seed: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func verifyingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> VerifyingKey {
    do {
      _ = try Ed25519PublicKey(bytes: rawRepresentation)
      return VerifyingKey(bytes: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
    do {
      let key = try Ed25519PrivateKey(seed: signingKey.seed.span)
      return VerifyingKey(bytes: Array(try key.publicKey()))
    } catch {
      preconditionFailure("validated Ed25519 signing key could not derive a public key")
    }
  }

  public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
    signingKey.seed
  }

  public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
    verifyingKey.bytes
  }

  public static func sign(
    _ message: Span<UInt8>,
    with signingKey: SigningKey
  ) throws(CryptoProviderError) -> [UInt8] {
    do {
      let key = try Ed25519PrivateKey(seed: signingKey.seed.span)
      return Array(try Ed25519.sign(message: message, using: key))
    } catch {
      throw .invalidSignature
    }
  }

  public static func isValid(
    signature: Span<UInt8>,
    for message: Span<UInt8>,
    with verifyingKey: VerifyingKey
  ) -> Bool {
    do {
      let key = try Ed25519PublicKey(bytes: verifyingKey.bytes.span)
      return try Ed25519.verify(
        signature: signature,
        message: message,
        using: key
      )
    } catch {
      return false
    }
  }
}

public enum DefaultProviderP256Signature: ProviderSignatureScheme {
  public struct SigningKey: Sendable {
    fileprivate let bytes: [UInt8]
  }

  public struct VerifyingKey: Sendable {
    fileprivate let bytes: [UInt8]
  }

  public static func generateSigningKey() throws(CryptoProviderError) -> SigningKey {
    do {
      let key = try P256PrivateKey.generate()
      return key.withBorrowedBytes { SigningKey(bytes: copyProviderBytes($0)) }
    } catch {
      throw .entropyFailure
    }
  }

  public static func signingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> SigningKey {
    do {
      _ = try P256PrivateKey(bytes: rawRepresentation)
      return SigningKey(bytes: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func verifyingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> VerifyingKey {
    do {
      _ = try P256PublicKey(bytes: rawRepresentation)
      return VerifyingKey(bytes: copyProviderBytes(rawRepresentation))
    } catch {
      throw .invalidKeyMaterial
    }
  }

  public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
    do {
      let key = try P256PrivateKey(bytes: signingKey.bytes.span)
      return VerifyingKey(bytes: copyProviderBytes(key.publicKey().span))
    } catch {
      preconditionFailure("validated P-256 signing key could not derive a public key")
    }
  }

  public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
    signingKey.bytes
  }

  public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
    verifyingKey.bytes
  }

  public static func sign(
    _ message: Span<UInt8>,
    with signingKey: SigningKey
  ) throws(CryptoProviderError) -> [UInt8] {
    do {
      let key = try P256PrivateKey(bytes: signingKey.bytes.span)
      var digest = ContiguousArray<UInt8>(
        repeating: 0,
        count: SHA256.digestByteCount
      )
      var destination = digest.mutableSpan
      try SHA256.hash(message, into: &destination)
      return Array(try P256ECDSA.sign(messageHash: digest.span, using: key))
    } catch {
      throw .invalidSignature
    }
  }

  public static func isValid(
    signature: Span<UInt8>,
    for message: Span<UInt8>,
    with verifyingKey: VerifyingKey
  ) -> Bool {
    do {
      let key = try P256PublicKey(bytes: verifyingKey.bytes.span)
      var digest = ContiguousArray<UInt8>(
        repeating: 0,
        count: SHA256.digestByteCount
      )
      var destination = digest.mutableSpan
      try SHA256.hash(message, into: &destination)
      return try P256ECDSA.verify(
        signature: signature,
        messageHash: digest.span,
        using: key
      )
    } catch {
      return false
    }
  }
}

/// P-256 signatures encoded as canonical ASN.1 DER for X.509 and libp2p wire use.
public enum DefaultProviderDERP256Signature: ProviderSignatureScheme {
  public typealias SigningKey = DefaultProviderP256Signature.SigningKey
  public typealias VerifyingKey = DefaultProviderP256Signature.VerifyingKey

  public static func generateSigningKey() throws(CryptoProviderError) -> SigningKey {
    try DefaultProviderP256Signature.generateSigningKey()
  }

  public static func signingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> SigningKey {
    try DefaultProviderP256Signature.signingKey(rawRepresentation: rawRepresentation)
  }

  public static func verifyingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> VerifyingKey {
    try DefaultProviderP256Signature.verifyingKey(rawRepresentation: rawRepresentation)
  }

  public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
    DefaultProviderP256Signature.verifyingKey(for: signingKey)
  }

  public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
    DefaultProviderP256Signature.rawRepresentation(of: signingKey)
  }

  public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
    DefaultProviderP256Signature.rawRepresentation(of: verifyingKey)
  }

  public static func sign(
    _ message: Span<UInt8>,
    with signingKey: SigningKey
  ) throws(CryptoProviderError) -> [UInt8] {
    let raw = try DefaultProviderP256Signature.sign(message, with: signingKey)
    do {
      return try DERECDSASignatureCodec.encode(
        rawSignature: raw.span,
        scalarByteCount: 32
      ).withBorrowedBytes { copyProviderBytes($0) }
    } catch {
      throw .invalidSignature
    }
  }

  public static func isValid(
    signature: Span<UInt8>,
    for message: Span<UInt8>,
    with verifyingKey: VerifyingKey
  ) -> Bool {
    do {
      let raw = try DERECDSASignatureCodec.decode(
        derSignature: signature,
        scalarByteCount: 32
      )
      return raw.withBorrowedBytes {
        DefaultProviderP256Signature.isValid(
          signature: $0,
          for: message,
          with: verifyingKey
        )
      }
    } catch {
      return false
    }
  }
}

public struct DefaultProviderRandomSource: ProviderRandomSource {
  public init() {}

  public func randomBytes(_ count: Int) throws(CryptoProviderError) -> [UInt8] {
    guard count >= 0 else {
      throw .invalidLength(expected: 0, actual: count)
    }
    var output = [UInt8](repeating: 0, count: count)
    try fill(&output)
    return output
  }

  public func fill(_ buffer: inout [UInt8]) throws(CryptoProviderError) {
    do {
      var destination = buffer.mutableSpan
      try SystemRandom.fill(&destination)
    } catch {
      throw .entropyFailure
    }
  }
}

/// Pure Swift primitive composition for portable protocol state machines.
public enum DefaultCryptoProvider: CryptoProvider {
  public typealias ChaChaPoly = DefaultProviderChaCha20Poly1305
  public typealias SHA256 = DefaultProviderSHA256
  public typealias HMACSHA256 = DefaultProviderHMACSHA256
  public typealias X25519 = DefaultProviderX25519
  public typealias Ed25519 = DefaultProviderEd25519
  public typealias P256Signature = DefaultProviderDERP256Signature
  public typealias RawP256Signature = DefaultProviderP256Signature
  public typealias Random = DefaultProviderRandomSource

  public static func makeChaChaPoly(
    key: Span<UInt8>
  ) throws(CryptoProviderError) -> DefaultProviderChaCha20Poly1305 {
    try DefaultProviderChaCha20Poly1305(key: key)
  }

  public static let random = DefaultProviderRandomSource()
}
