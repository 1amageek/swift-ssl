import SwiftSSLCore

/// Server-side ownership and encapsulation contract for one TLS 1.3 key share.
public protocol TLS13ServerKeyExchange: ~Copyable, Sendable {
    var namedGroup: TLS13NamedGroup { get }

    mutating func accept(
        clientShare: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> TLS13ServerKeyExchangeResult
}
