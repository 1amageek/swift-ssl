/// Errors raised by allocating cryptographic provider adapters.
///
/// Primitive implementations keep their precise low-level errors. This error
/// is the stable boundary used by generic protocol state machines that compose
/// several primitives and exchange owned byte values.
public enum CryptoProviderError: Error, Equatable, Sendable {
  case authenticationFailure
  case invalidLength(expected: Int, actual: Int)
  case invalidKeyMaterial
  case keyAgreementFailure
  case invalidSignature
  case entropyFailure
  case primitiveFailure
}

/// A reusable keyed authenticated cipher that returns owned protocol output.
public protocol ProviderAuthenticatedCipher: Sendable {
  static var nonceByteCount: Int { get }
  static var tagByteCount: Int { get }

  func seal(
    _ plaintext: Span<UInt8>,
    nonce: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(CryptoProviderError) -> [UInt8]

  func open(
    _ ciphertextAndTag: Span<UInt8>,
    nonce: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(CryptoProviderError) -> [UInt8]
}

/// An allocating incremental hash adapter for generic protocol state machines.
public protocol ProviderHashFunction: ~Copyable, Sendable {
  static var digestByteCount: Int { get }
  init()
  mutating func update(_ bytes: Span<UInt8>)
  consuming func finalize() -> [UInt8]
}

extension ProviderHashFunction where Self: ~Copyable {
  public static func hash(_ bytes: Span<UInt8>) -> [UInt8] {
    var context = Self()
    context.update(bytes)
    return context.finalize()
  }
}

/// An allocating message-authentication adapter.
public protocol ProviderMessageAuthenticationCode: Sendable {
  static var tagByteCount: Int { get }
  static func authenticate(
    _ message: Span<UInt8>,
    using key: Span<UInt8>
  ) -> [UInt8]
}

/// Copyable key handles used by generic protocol state machines.
///
/// Concrete providers may store immutable key bytes or a reference-counted key
/// owner. Key import, agreement, and serialization remain explicit operations.
public protocol ProviderKeyAgreement: Sendable {
  associatedtype PrivateKey: Sendable
  associatedtype PublicKey: Sendable

  static func generatePrivateKey() throws(CryptoProviderError) -> PrivateKey
  static func privateKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> PrivateKey
  static func publicKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> PublicKey
  static func publicKey(for privateKey: PrivateKey) -> PublicKey
  static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8]
  static func rawRepresentation(of publicKey: PublicKey) -> [UInt8]
  static func sharedSecret(
    privateKey: PrivateKey,
    peerPublicKey: PublicKey
  ) throws(CryptoProviderError) -> [UInt8]
}

/// Copyable signing-key handles used at long-lived protocol ownership boundaries.
public protocol ProviderSignatureScheme: Sendable {
  associatedtype SigningKey: Sendable
  associatedtype VerifyingKey: Sendable

  static func generateSigningKey() throws(CryptoProviderError) -> SigningKey
  static func signingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> SigningKey
  static func verifyingKey(
    rawRepresentation: Span<UInt8>
  ) throws(CryptoProviderError) -> VerifyingKey
  static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey
  static func rawRepresentation(of signingKey: SigningKey) -> [UInt8]
  static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8]
  static func sign(
    _ message: Span<UInt8>,
    with signingKey: SigningKey
  ) throws(CryptoProviderError) -> [UInt8]
  static func isValid(
    signature: Span<UInt8>,
    for message: Span<UInt8>,
    with verifyingKey: VerifyingKey
  ) -> Bool
}

/// Cryptographically secure random-byte generation for protocol values.
public protocol ProviderRandomSource: Sendable {
  func randomBytes(_ count: Int) throws(CryptoProviderError) -> [UInt8]
  func fill(_ buffer: inout [UInt8]) throws(CryptoProviderError)
}

/// Static-dispatch composition used by portable protocol state machines.
///
/// The primitive contracts remain independently usable. This aggregate names
/// only the algorithms jointly required by the portable libp2p security path.
public protocol CryptoProvider: Sendable {
  associatedtype ChaChaPoly: ProviderAuthenticatedCipher
  associatedtype SHA256: ~Copyable & ProviderHashFunction
  associatedtype HMACSHA256: ProviderMessageAuthenticationCode
  associatedtype X25519: ProviderKeyAgreement
  associatedtype Ed25519: ProviderSignatureScheme
  associatedtype P256Signature: ProviderSignatureScheme
  associatedtype RawP256Signature: ProviderSignatureScheme
  associatedtype Random: ProviderRandomSource

  static func makeChaChaPoly(
    key: Span<UInt8>
  ) throws(CryptoProviderError) -> ChaChaPoly

  static var random: Random { get }
}
