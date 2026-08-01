import SwiftSSLCore

/// An owned FIPS 204 ML-DSA-65 public key.
public struct MLDSA65PublicKey: Sendable, Equatable {
  public static let byteCount = MLDSA65.publicKeyByteCount

  private let storage: OwnedBytes
  let expanded: MLDSA65ExpandedPublicKey

  public init(bytes: Span<UInt8>) throws(MLDSAError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidPublicKeyLength(expected: Self.byteCount, actual: bytes.count)
    }
    let owned = OwnedBytes(copying: bytes)
    let decoded = try MLDSA65Core.expandPublicKey(owned.span)
    storage = owned
    expanded = decoded
  }

  init(owned bytes: OwnedBytes) throws(MLDSAError) {
    precondition(bytes.count == Self.byteCount)
    let decoded = try MLDSA65Core.expandPublicKey(bytes.span)
    storage = bytes
    expanded = decoded
  }

  init(
    owned bytes: OwnedBytes,
    expanded: MLDSA65ExpandedPublicKey
  ) {
    precondition(bytes.count == Self.byteCount)
    storage = bytes
    self.expanded = expanded
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(storage.span)
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    ConstantTime.equal(lhs.span, rhs.span)
  }
}
