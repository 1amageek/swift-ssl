import SSLTypes

/// The protocol-facing spelling is retained while the value itself is owned
/// by `SSLTypes`. This keeps ALPN vocabulary independent from the TLS state
/// machine and prevents a second byte-owning implementation from appearing in
/// `SSLTLS`.
public typealias TLS13ApplicationProtocol = TLSApplicationProtocol

extension TLSApplicationProtocol {
  /// Constructs the canonical vocabulary value from the historical TLS
  /// mechanism label. The error is mapped at this protocol boundary so the
  /// vocabulary module does not depend on `SSLTLS`.
  public init(
    identifier: Span<UInt8>
  ) throws(TLS13ApplicationProtocolError) {
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(identifier.count)
    var index = 0
    while index < identifier.count {
      bytes.append(identifier[index])
      index += 1
    }

    do {
      self = try TLSApplicationProtocol(bytes: consume bytes)
    } catch let error {
      switch error {
      case .invalidLength(let actual):
        throw .invalidIdentifierLength(actual: actual)
      }
    }
  }

  public borrowing func withIdentifierBytes<Result, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try withBytes(body)
  }
}
