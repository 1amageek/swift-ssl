import SwiftSSLCore

/// Context-bound randomized signing with caller-owned signature storage.
public protocol InPlaceContextualRandomizedDigitalSignature:
  ContextualRandomizedDigitalSignature
{
  static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing PrivateKey,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError)
}
