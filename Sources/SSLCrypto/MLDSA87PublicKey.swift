import SSLCore

/// An owned FIPS 204 ML-DSA-87 public key.
public struct MLDSA87PublicKey: Sendable, Equatable {
  public static let byteCount = MLDSA87.publicKeyByteCount

  private let storage: OwnedBytes
  let expanded: MLDSAExpandedPublicKey

  private static var core: MLDSACore {
    MLDSACore(parameterSet: .mlDSA87)
  }

  public init(bytes: Span<UInt8>) throws(MLDSAError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidPublicKeyLength(expected: Self.byteCount, actual: bytes.count)
    }
    let owned = OwnedBytes(copying: bytes)
    let decoded = try Self.core.expandPublicKey(owned.span)
    storage = owned
    expanded = decoded
  }

  init(owned bytes: OwnedBytes) throws(MLDSAError) {
    precondition(bytes.count == Self.byteCount)
    let decoded = try Self.core.expandPublicKey(bytes.span)
    storage = bytes
    expanded = decoded
  }

  init(
    owned bytes: OwnedBytes,
    expanded: MLDSAExpandedPublicKey
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
