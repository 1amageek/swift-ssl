/// DTLS 1.2 Key Schedule (RFC 5246 §8.1), Embedded-clean.
///
/// Derives `master_secret` from the pre-master secret and the handshake randoms,
/// then expands `key_block` (client/server write keys + IVs) and `verify_data`
/// (Finished) through an injected ``DTLSPRFContext``.
///
/// ```
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
/// key_block     = PRF(master_secret, "key expansion",
///                     server_random + client_random)
/// verify_data   = PRF(master_secret, finished_label, handshake_hash)[0..11]
/// ```
///
/// A single value type; the negotiated cipher suite selects the hash. The
/// `master secret` is held privately and out-of-order use throws
/// ``DTLSWireCore/DTLSError`` (no silent fallback).
///
/// The concrete provider is selected by the adapter when it creates the immutable
/// PRF context. Embedded-clean: no Foundation, no `any`, no Mutex, no
/// swift-crypto, typed throws.

import P2PCoreBytes
import DTLSWireCore

/// Key block derived from the DTLS 1.2 master secret (raw `[UInt8]`).
public struct DTLSKeyBlockCore: Sendable, Equatable {
    public let clientWriteKey: [UInt8]
    public let serverWriteKey: [UInt8]
    public let clientWriteIV: [UInt8]
    public let serverWriteIV: [UInt8]

    public init(
        clientWriteKey: [UInt8],
        serverWriteKey: [UInt8],
        clientWriteIV: [UInt8],
        serverWriteIV: [UInt8]
    ) {
        self.clientWriteKey = clientWriteKey
        self.serverWriteKey = serverWriteKey
        self.clientWriteIV = clientWriteIV
        self.serverWriteIV = serverWriteIV
    }
}

/// The DTLS 1.2 key schedule over the crypto MAC seam.
public struct DTLSKeyScheduleCore: Sendable {
    public let cipherSuite: DTLSCipherSuite
    private let prfContext: DTLSPRFContext
    private var masterSecret: [UInt8]?
    private var clientRandom: [UInt8]?
    private var serverRandom: [UInt8]?
    private var extendedMasterSecretSessionHash: [UInt8]?

    public init(
        cipherSuite: DTLSCipherSuite,
        prfContext: DTLSPRFContext
    ) {
        self.cipherSuite = cipherSuite
        self.prfContext = prfContext
        self.masterSecret = nil
        self.clientRandom = nil
        self.serverRandom = nil
        self.extendedMasterSecretSessionHash = nil
    }

    /// Whether the master secret has been derived.
    public var hasMasterSecret: Bool { masterSecret != nil }

    /// Configures RFC 7627 before the ECDHE secret is folded into the schedule.
    /// The hash must cover the complete handshake transcript through
    /// ClientKeyExchange (RFC 7627 section 3).
    public mutating func configureExtendedMasterSecret(sessionHash: [UInt8]) {
        self.extendedMasterSecretSessionHash = sessionHash
    }

    /// `master_secret = PRF(pre_master_secret, "master secret",
    ///   client_random + server_random)[0..47]`.
    public mutating func deriveMasterSecret(
        preMasterSecret: [UInt8],
        clientRandom: [UInt8],
        serverRandom: [UInt8]
    ) {
        let label = extendedMasterSecretSessionHash == nil
            ? "master secret"
            : "extended master secret"
        let seed: [UInt8]
        if let extendedMasterSecretSessionHash {
            seed = extendedMasterSecretSessionHash
        } else {
            var randomSeed = [UInt8]()
            randomSeed.reserveCapacity(clientRandom.count + serverRandom.count)
            randomSeed.append(contentsOf: clientRandom)
            randomSeed.append(contentsOf: serverRandom)
            seed = randomSeed
        }
        self.masterSecret = prfContext.compute(
            secret: preMasterSecret,
            label: label,
            seed: seed,
            length: 48,
            hash: cipherSuite.hashAlgorithm
        )
        self.clientRandom = clientRandom
        self.serverRandom = serverRandom
    }

    /// `key_block = PRF(master_secret, "key expansion",
    ///   server_random + client_random)` split into the write keys and IVs.
    public func deriveKeyBlock() throws(DTLSError) -> DTLSKeyBlockCore {
        guard let masterSecret, let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Master secret not derived")
        }

        // key_block uses server_random + client_random (reversed from master_secret).
        var seed = [UInt8]()
        seed.reserveCapacity(serverRandom.count + clientRandom.count)
        seed.append(contentsOf: serverRandom)
        seed.append(contentsOf: clientRandom)

        let keyLength = cipherSuite.keyLength
        let ivLength = cipherSuite.fixedIVLength
        let totalLength = 2 * keyLength + 2 * ivLength

        let keyBlock = prfContext.compute(
            secret: masterSecret,
            label: "key expansion",
            seed: seed,
            length: totalLength,
            hash: cipherSuite.hashAlgorithm
        )

        var offset = 0
        let clientWriteKey = Array(keyBlock[offset..<offset + keyLength])
        offset += keyLength
        let serverWriteKey = Array(keyBlock[offset..<offset + keyLength])
        offset += keyLength
        let clientWriteIV = Array(keyBlock[offset..<offset + ivLength])
        offset += ivLength
        let serverWriteIV = Array(keyBlock[offset..<offset + ivLength])

        return DTLSKeyBlockCore(
            clientWriteKey: clientWriteKey,
            serverWriteKey: serverWriteKey,
            clientWriteIV: clientWriteIV,
            serverWriteIV: serverWriteIV
        )
    }

    /// `verify_data = PRF(master_secret, label, handshake_hash)[0..11]`.
    public func computeVerifyData(
        label: String,
        handshakeHash: [UInt8]
    ) throws(DTLSError) -> [UInt8] {
        guard let masterSecret else {
            throw DTLSError.invalidState("Master secret not derived")
        }
        return prfContext.compute(
            secret: masterSecret,
            label: label,
            seed: handshakeHash,
            length: 12,
            hash: cipherSuite.hashAlgorithm
        )
    }

    /// RFC 5705 exporter using the negotiated DTLS 1.2 PRF.
    ///
    /// `context == nil` means that no context field is present. A non-`nil` empty
    /// context is distinct and contributes a zero 16-bit context length.
    public func exportKeyingMaterial(
        label: String,
        context: [UInt8]?,
        length: Int
    ) throws(DTLSError) -> [UInt8] {
        guard let masterSecret, let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Master secret not derived")
        }
        guard (0...65_535).contains(length) else {
            throw DTLSError.invalidFormat("Exporter length must be between 0 and 65535 bytes")
        }
        let labelBytes = [UInt8](label.utf8)
        guard !labelBytes.isEmpty, labelBytes.allSatisfy({ (0x20...0x7E).contains($0) }) else {
            throw DTLSError.invalidFormat("Exporter label must be non-empty printable ASCII")
        }
        let reservedLabels = ["client finished", "server finished", "master secret", "key expansion"]
        guard !reservedLabels.contains(label) else {
            throw DTLSError.invalidFormat("Exporter label collides with a reserved TLS PRF label")
        }

        var seed: [UInt8] = []
        seed.reserveCapacity(
            clientRandom.count + serverRandom.count + (context.map { 2 + $0.count } ?? 0)
        )
        seed.append(contentsOf: clientRandom)
        seed.append(contentsOf: serverRandom)
        if let context {
            guard context.count <= Int(UInt16.max) else {
                throw DTLSError.invalidFormat("Exporter context exceeds 65535 bytes")
            }
            seed.append(UInt8((context.count >> 8) & 0xFF))
            seed.append(UInt8(context.count & 0xFF))
            seed.append(contentsOf: context)
        }

        return prfContext.compute(
            secret: masterSecret,
            label: label,
            seed: seed,
            length: length,
            hash: cipherSuite.hashAlgorithm
        )
    }
}
