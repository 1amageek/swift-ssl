import SSLCore

struct TLS13ServerKeyExchangeState: ~Copyable, Sendable {
    let namedGroup: TLS13NamedGroup
    private var p256: TLS13P256ServerKeyExchange?
    private var x25519: TLS13X25519ServerKeyExchange?
    private var x25519MLKEM768: TLS13X25519MLKEM768ServerKeyExchange?

    init(p256: consuming TLS13P256ServerKeyExchange) {
        namedGroup = .secp256r1
        self.p256 = consume p256
        x25519 = nil
        x25519MLKEM768 = nil
    }

    init(x25519: consuming TLS13X25519ServerKeyExchange) {
        namedGroup = .x25519
        p256 = nil
        self.x25519 = consume x25519
        x25519MLKEM768 = nil
    }

    init(x25519MLKEM768: consuming TLS13X25519MLKEM768ServerKeyExchange) {
        namedGroup = .x25519MLKEM768
        p256 = nil
        x25519 = nil
        self.x25519MLKEM768 = consume x25519MLKEM768
    }

    mutating func accept(
        clientShare: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws(TLS13KeyExchangeError) -> TLS13ServerKeyExchangeResult {
        switch namedGroup {
        case .secp256r1:
            guard var exchange = p256.take() else {
                throw .invalidState
            }
            return try exchange.accept(clientShare: clientShare, using: entropy)
        case .x25519:
            guard var exchange = x25519.take() else {
                throw .invalidState
            }
            return try exchange.accept(clientShare: clientShare, using: entropy)
        case .x25519MLKEM768:
            guard var exchange = x25519MLKEM768.take() else {
                throw .invalidState
            }
            return try exchange.accept(clientShare: clientShare, using: entropy)
        }
    }
}
