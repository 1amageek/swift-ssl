import SSLCore

/// An owned, validated Ed25519 public key.
public struct Ed25519PublicKey: Sendable, Equatable {
  public static let byteCount = Ed25519.publicKeyByteCount

  private let storage: OwnedBytes
  let decodedPoint: EdwardsPoint

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    decodedPoint = try EdwardsPoint.decode(bytes)
    storage = OwnedBytes(copying: bytes)
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.storage == rhs.storage
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(storage.span)
  }
}
