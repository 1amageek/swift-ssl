import SwiftSSLCore

struct TLS13ClientKeyExchangeState: ~Copyable, Sendable {
    let namedGroup: TLS13NamedGroup
    private var x25519: TLS13X25519ClientKeyExchange?
    private var x25519MLKEM768: TLS13X25519MLKEM768ClientKeyExchange?

    init(x25519: consuming TLS13X25519ClientKeyExchange) {
        namedGroup = .x25519
        self.x25519 = consume x25519
        x25519MLKEM768 = nil
    }

    init(x25519MLKEM768: consuming TLS13X25519MLKEM768ClientKeyExchange) {
        namedGroup = .x25519MLKEM768
        x25519 = nil
        self.x25519MLKEM768 = consume x25519MLKEM768
    }

    borrowing func withClientShare<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        switch namedGroup {
        case .x25519:
            return try x25519!.withClientShare(body)
        case .x25519MLKEM768:
            return try x25519MLKEM768!.withClientShare(body)
        }
    }

    mutating func complete(
        serverShare: Span<UInt8>
    ) throws(TLS13KeyExchangeError) -> SecretBytes {
        switch namedGroup {
        case .x25519:
            guard var exchange = x25519.take() else {
                throw .invalidState
            }
            return try exchange.complete(serverShare: serverShare)
        case .x25519MLKEM768:
            guard var exchange = x25519MLKEM768.take() else {
                throw .invalidState
            }
            return try exchange.complete(serverShare: serverShare)
        }
    }
}
