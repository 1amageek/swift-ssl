import SwiftSSLCore

/// Uniquely owned RFC 5764 keying material in exporter wire order.
public struct DTLSSRTPKeyingMaterial: ~Copyable, Sendable {
  public let protectionProfile: DTLSSRTPProtectionProfile
  public let masterKeyIdentifier: OwnedBytes
  private let secret: SecretBytes

  package init(
    protectionProfile: DTLSSRTPProtectionProfile,
    masterKeyIdentifier: OwnedBytes,
    secret: consuming SecretBytes
  ) {
    self.protectionProfile = protectionProfile
    self.masterKeyIdentifier = masterKeyIdentifier
    self.secret = secret
  }

  public borrowing func withClientWriteMasterKey<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try withRange(offset: 0, count: protectionProfile.masterKeyByteCount, body)
  }

  public borrowing func withServerWriteMasterKey<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try withRange(
      offset: protectionProfile.masterKeyByteCount,
      count: protectionProfile.masterKeyByteCount,
      body
    )
  }

  public borrowing func withClientWriteMasterSalt<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try withRange(
      offset: 2 * protectionProfile.masterKeyByteCount,
      count: protectionProfile.masterSaltByteCount,
      body
    )
  }

  public borrowing func withServerWriteMasterSalt<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try withRange(
      offset: 2 * protectionProfile.masterKeyByteCount
        + protectionProfile.masterSaltByteCount,
      count: protectionProfile.masterSaltByteCount,
      body
    )
  }

  private borrowing func withRange<Result: ~Copyable, Failure: Error>(
    offset: Int,
    count: Int,
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try secret.withBorrowedBytes { bytes throws(Failure) in
      try body(bytes.extracting(offset..<(offset + count)))
    }
  }
}
