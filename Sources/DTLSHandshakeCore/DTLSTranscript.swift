/// DTLS 1.2 handshake transcript hashing, Embedded-clean.
///
/// DTLS 1.2 hashes the full accumulated handshake-message buffer at several
/// points. The selected provider supplies concrete SHA-256 and SHA-384 functions
/// when the engine is configured, so the handshake runtime does not cross a
/// generic provider witness boundary on normal WASM.

import DTLSWireCore

/// Immutable owner of the concrete transcript hash operations.
public final class DTLSTranscriptContext: Sendable {
    public typealias Hash = @Sendable (_ message: [UInt8]) -> [UInt8]

    private let sha256: Hash
    private let sha384: Hash

    public init(
        sha256: @escaping Hash,
        sha384: @escaping Hash
    ) {
        self.sha256 = sha256
        self.sha384 = sha384
    }

    /// Returns `Hash(messages)` for the negotiated cipher suite.
    public func hash(
        messages: [UInt8],
        cipherSuite: DTLSCipherSuite?
    ) -> [UInt8] {
        switch cipherSuite?.hashAlgorithm {
        case .sha384:
            return sha384(messages)
        default:
            return sha256(messages)
        }
    }
}
