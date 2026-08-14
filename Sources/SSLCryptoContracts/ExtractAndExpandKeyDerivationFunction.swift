
/// A key derivation function with independently usable extract and expand stages.
public protocol ExtractAndExpandKeyDerivationFunction: Sendable {
  associatedtype Failure: Error

  /// The byte count produced by the extract stage.
  static var pseudorandomKeyByteCount: Int { get }

  /// The largest output accepted by the expand stage.
  static var maximumOutputByteCount: Int { get }

  /// Extracts a fixed-size pseudorandom key into an exactly sized output span.
  ///
  /// Input and output storage must not overlap. A conformer rejects validation
  /// failures before mutation. After any other thrown failure, callers must
  /// discard and wipe the entire output because its contents are unspecified.
  static func extract(
    inputKeyMaterial: Span<UInt8>,
    salt: Span<UInt8>,
    into pseudorandomKey: inout MutableSpan<UInt8>
  ) throws(Failure)

  /// Expands a pseudorandom key into the complete caller-owned output span.
  ///
  /// Input and output storage must not overlap. A conformer rejects validation
  /// failures before mutation. After any other thrown failure, callers must
  /// discard and wipe the entire output because its contents are unspecified.
  static func expand(
    pseudorandomKey: Span<UInt8>,
    info: Span<UInt8>,
    into outputKeyMaterial: inout MutableSpan<UInt8>
  ) throws(Failure)
}
