import SwiftSSLCore

/// Client-side ownership and completion contract for one TLS 1.3 key share.
public protocol TLS13ClientKeyExchange: ~Copyable, Sendable {
    var namedGroup: TLS13NamedGroup { get }

    borrowing func withClientShare<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result

    mutating func complete(
        serverShare: Span<UInt8>
    ) throws(TLS13KeyExchangeError) -> SecretBytes
}
