/// TLS 1.2 / DTLS 1.2 PRF (RFC 5246 Section 5), Embedded-clean.
///
/// ```
/// PRF(secret, label, seed) = P_hash(secret, label + seed)
/// P_hash(secret, seed) = HMAC(secret, A(1) + seed) ||
///                        HMAC(secret, A(2) + seed) || ...
/// A(0) = seed
/// A(i) = HMAC(secret, A(i-1))
/// ```
///
/// The selected crypto provider supplies concrete SHA-256 and SHA-384 HMAC
/// functions once, when the engine configuration is built. The handshake core
/// therefore does not invoke a `CryptoProvider` associated-type witness while a
/// handshake is running. This is important on normal WASM, where cross-module
/// generic protocol witnesses are not a reliable runtime ownership boundary.
///
/// Each HMAC function accepts two input segments. Implementations update one MAC
/// context with both segments, avoiding a temporary `A(i) + seed` allocation on
/// every expansion round. The arrays use copy-on-write storage and are only
/// borrowed by the injected function.

import DTLSWireCore

/// Immutable owner of the concrete HMAC operations used by the DTLS PRF.
public final class DTLSPRFContext: Sendable {
    /// Computes HMAC over `first`, followed by `second` when present.
    ///
    /// Implementations must consume both segments in order without retaining
    /// either input beyond the call.
    public typealias SegmentedAuthenticationCode = @Sendable (
        _ first: [UInt8],
        _ second: [UInt8]?,
        _ key: [UInt8]
    ) -> [UInt8]

    private let hmacSHA256: SegmentedAuthenticationCode
    private let hmacSHA384: SegmentedAuthenticationCode

    public init(
        hmacSHA256: @escaping SegmentedAuthenticationCode,
        hmacSHA384: @escaping SegmentedAuthenticationCode
    ) {
        self.hmacSHA256 = hmacSHA256
        self.hmacSHA384 = hmacSHA384
    }

    /// Computes `PRF(secret, label, seed)` with the negotiated hash.
    public func compute(
        secret: [UInt8],
        label: String,
        seed: [UInt8],
        length: Int,
        hash: HashAlgorithm
    ) -> [UInt8] {
        var combined = [UInt8]()
        combined.reserveCapacity(label.utf8.count + seed.count)
        combined.append(contentsOf: label.utf8)
        combined.append(contentsOf: seed)

        switch hash {
        case .sha256:
            return pHash(
                secret: secret,
                seed: combined,
                length: length,
                authenticate: hmacSHA256
            )
        case .sha384:
            return pHash(
                secret: secret,
                seed: combined,
                length: length,
                authenticate: hmacSHA384
            )
        }
    }

    private func pHash(
        secret: [UInt8],
        seed: [UInt8],
        length: Int,
        authenticate: SegmentedAuthenticationCode
    ) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(length)

        var a = seed
        while result.count < length {
            a = authenticate(a, nil, secret)
            let block = authenticate(a, seed, secret)
            result.append(contentsOf: block)
        }
        if result.count > length {
            result.removeLast(result.count - length)
        }
        return result
    }
}
