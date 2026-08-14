
/// Derives password-based key material directly into caller-owned storage.
public protocol PasswordBasedKeyDerivationFunction: Sendable {
  associatedtype Failure: Error

  static func deriveKey(
    password: Span<UInt8>,
    salt: Span<UInt8>,
    iterations: UInt32,
    into output: inout MutableSpan<UInt8>
  ) throws(Failure)
}
