import SwiftSSLCore
import SwiftSSLCrypto

/// RFC 8446 TLS 1.3 key schedule for the supported SHA-256/SHA-384 suites.
public struct TLS13KeySchedule: ~Copyable, Sendable {
    public let cipherSuite: TLSCipherSuite
    private let earlySecret: SecretBytes

    public init(
        cipherSuite: TLSCipherSuite,
        preSharedKey: Span<UInt8>
    ) throws(TLS13KeyScheduleError) {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        guard preSharedKey.count <= 64 * 1024 else {
            throw .invalidPreSharedKeyLength(actual: preSharedKey.count)
        }
        let zeroSalt = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
        let early = try Self.extract(
            salt: zeroSalt.span,
            inputKeyMaterial: preSharedKey,
            cipherSuite: cipherSuite
        )
        self.cipherSuite = cipherSuite
        earlySecret = early
    }

    public borrowing func makeHandshakeSecrets(
        ecdheSharedSecret: Span<UInt8>,
        transcriptHash: Span<UInt8>
    ) throws(TLS13KeyScheduleError) -> TLS13HandshakeSecrets {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        // X25519 always produces a 32-byte shared secret; the hash size only
        // controls the transcript and traffic-secret widths.
        guard ecdheSharedSecret.count == X25519SharedSecret.byteCount else {
            throw .invalidECDHESecretLength(actual: ecdheSharedSecret.count)
        }
        guard transcriptHash.count == hashByteCount else {
            throw .invalidTranscriptHashLength(expected: hashByteCount, actual: transcriptHash.count)
        }

        let emptyHash = try Self.hashEmptyMessage(cipherSuite: cipherSuite)
        let derivedEarly = try Self.deriveSecret(
            secret: earlySecret,
            label: "derived",
            transcriptHash: emptyHash.span,
            cipherSuite: cipherSuite
        )
        let handshakeSecret = try Self.extract(
            salt: derivedEarly,
            inputKeyMaterial: ecdheSharedSecret,
            cipherSuite: cipherSuite
        )
        let client = try Self.deriveSecret(
            secret: handshakeSecret,
            label: "c hs traffic",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        let server = try Self.deriveSecret(
            secret: handshakeSecret,
            label: "s hs traffic",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        let derivedHandshake = try Self.deriveSecret(
            secret: handshakeSecret,
            label: "derived",
            transcriptHash: emptyHash.span,
            cipherSuite: cipherSuite
        )
        let zeroInput = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
        let master = try Self.extract(
            salt: derivedHandshake,
            inputKeyMaterial: zeroInput.span,
            cipherSuite: cipherSuite
        )
        return TLS13HandshakeSecrets(
            cipherSuite: cipherSuite,
            clientTrafficSecret: client,
            serverTrafficSecret: server,
            masterSecret: master
        )
    }

    static func hashByteCount(for suite: TLSCipherSuite) -> Int {
        suite == .aes256GCM_SHA384 ? 48 : 32
    }

    static func deriveSecret(
        secret: borrowing SecretBytes,
        label: String,
        transcriptHash: Span<UInt8>,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        guard transcriptHash.count == hashByteCount else {
            throw .invalidTranscriptHashLength(expected: hashByteCount, actual: transcriptHash.count)
        }
        var info = ContiguousArray<UInt8>()
        info.reserveCapacity(2 + 1 + 6 + label.utf8.count + 1 + transcriptHash.count)
        info.append(UInt8(truncatingIfNeeded: hashByteCount >> 8))
        info.append(UInt8(truncatingIfNeeded: hashByteCount))
        info.append(UInt8(truncatingIfNeeded: 6 + label.utf8.count))
        info.append(contentsOf: "tls13 ".utf8)
        info.append(contentsOf: label.utf8)
        info.append(UInt8(truncatingIfNeeded: transcriptHash.count))
        var hashIndex = 0
        while hashIndex < transcriptHash.count {
            info.append(transcriptHash[hashIndex])
            hashIndex += 1
        }
        return try Self.expand(
            secret: secret,
            info: info.span,
            outputByteCount: hashByteCount,
            cipherSuite: cipherSuite
        )
    }

    /// Derives the next sending or receiving traffic secret from RFC 8446
    /// section 7.2. The update label has an empty context, unlike
    /// `Derive-Secret`, which hashes a transcript before expanding.
    static func updateTrafficSecret(
        secret: borrowing SecretBytes,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        var info = ContiguousArray<UInt8>()
        info.reserveCapacity(2 + 1 + 17 + 1)
        info.append(UInt8(truncatingIfNeeded: hashByteCount >> 8))
        info.append(UInt8(truncatingIfNeeded: hashByteCount))
        info.append(17)
        info.append(contentsOf: "tls13 traffic upd".utf8)
        info.append(0)
        return try Self.expand(
            secret: secret,
            info: info.span,
            outputByteCount: hashByteCount,
            cipherSuite: cipherSuite
        )
    }

    static func deriveResumptionPSK(
        resumptionMasterSecret: borrowing SecretBytes,
        ticketNonce: Span<UInt8>,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        var nonceHash = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
        do {
            var destination = nonceHash.mutableSpan
            switch cipherSuite {
            case .aes256GCM_SHA384:
                try SHA384.hash(ticketNonce, into: &destination)
            case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                try SHA256.hash(ticketNonce, into: &destination)
            }
        } catch {
            throw .cryptographicFailure
        }
        defer { wipe(&nonceHash) }
        return try Self.deriveSecret(
            secret: resumptionMasterSecret,
            label: "resumption",
            transcriptHash: nonceHash.span,
            cipherSuite: cipherSuite
        )
    }

    static func finishedVerifyData(
        trafficSecret: borrowing SecretBytes,
        transcriptHash: Span<UInt8>,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> OwnedBytes {
        let emptyHash = Self.hashEmptyMessageBytes(cipherSuite: cipherSuite)
        let finishedKey = try Self.deriveSecret(
            secret: trafficSecret,
            label: "finished",
            transcriptHash: emptyHash.span,
            cipherSuite: cipherSuite
        )
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        guard transcriptHash.count == hashByteCount else {
            throw .invalidTranscriptHashLength(expected: hashByteCount, actual: transcriptHash.count)
        }
        var output = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
        let outputByteCount = output.count
        do {
            try finishedKey.withBorrowedBytes { key in
                try output.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
                    var destination = MutableSpan(_unsafeStart: buffer.baseAddress!, count: outputByteCount)
                    switch cipherSuite {
                    case .aes256GCM_SHA384:
                        try HMACSHA384.authenticate(transcriptHash, using: key, into: &destination)
                    case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                        try HMACSHA256.authenticate(transcriptHash, using: key, into: &destination)
                    }
                }
            }
        } catch {
            wipe(&output)
            throw .cryptographicFailure
        }
        return OwnedBytes(consuming: output)
    }

    private static func expand(
        secret: borrowing SecretBytes,
        info: Span<UInt8>,
        outputByteCount: Int,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        defer { wipe(&output) }
        do {
            try secret.withBorrowedBytes { secretBytes in
                try output.withUnsafeMutableBufferPointer { buffer throws(HKDFError) in
                    let baseAddress = buffer.baseAddress!
                    var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
                    switch cipherSuite {
                    case .aes256GCM_SHA384:
                        try HKDFSHA384.expand(
                            pseudorandomKey: secretBytes,
                            info: info,
                            into: &destination
                        )
                    case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                        try HKDFSHA256.expand(
                            pseudorandomKey: secretBytes,
                            info: info,
                            into: &destination
                        )
                    }
                }
            }
        } catch {
            throw .cryptographicFailure
        }
        do {
            return try SecretBytes(copying: output.span)
        } catch {
            throw .invalidSecretMemory
        }
    }

    private static func extract(
        salt: Span<UInt8>,
        inputKeyMaterial: Span<UInt8>,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        let outputByteCount = Self.hashByteCount(for: cipherSuite)
        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        defer { wipe(&output) }
        do {
            try output.withUnsafeMutableBufferPointer { buffer throws(HKDFError) in
                let baseAddress = buffer.baseAddress!
                var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
                switch cipherSuite {
                case .aes256GCM_SHA384:
                    try HKDFSHA384.extract(
                        inputKeyMaterial: inputKeyMaterial,
                        salt: salt,
                        into: &destination
                    )
                case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                    try HKDFSHA256.extract(
                        inputKeyMaterial: inputKeyMaterial,
                        salt: salt,
                        into: &destination
                    )
                }
            }
        } catch {
            throw .cryptographicFailure
        }
        do {
            return try SecretBytes(copying: output.span)
        } catch {
            throw .invalidSecretMemory
        }
    }

    private static func extract(
        salt: borrowing SecretBytes,
        inputKeyMaterial: Span<UInt8>,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> SecretBytes {
        let outputByteCount = Self.hashByteCount(for: cipherSuite)
        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        defer { wipe(&output) }
        do {
            try salt.withBorrowedBytes { saltBytes in
                try output.withUnsafeMutableBufferPointer { buffer throws(HKDFError) in
                    let baseAddress = buffer.baseAddress!
                    var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
                    switch cipherSuite {
                    case .aes256GCM_SHA384:
                        try HKDFSHA384.extract(
                            inputKeyMaterial: inputKeyMaterial,
                            salt: saltBytes,
                            into: &destination
                        )
                    case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                        try HKDFSHA256.extract(
                            inputKeyMaterial: inputKeyMaterial,
                            salt: saltBytes,
                            into: &destination
                        )
                    }
                }
            }
        } catch {
            throw .cryptographicFailure
        }
        do {
            return try SecretBytes(copying: output.span)
        } catch {
            throw .invalidSecretMemory
        }
    }

    private static func hashEmptyMessage(
        cipherSuite: TLSCipherSuite
    ) throws(TLS13KeyScheduleError) -> OwnedBytes {
        let outputByteCount = Self.hashByteCount(for: cipherSuite)
        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        let emptyInput = ContiguousArray<UInt8>()
        do {
            try output.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
                let baseAddress = buffer.baseAddress!
                var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
                switch cipherSuite {
                case .aes256GCM_SHA384:
                    try SHA384.hash(emptyInput.span, into: &destination)
                case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                    try SHA256.hash(emptyInput.span, into: &destination)
                }
            }
        } catch {
            throw .cryptographicFailure
        }
        return OwnedBytes(consuming: output)
    }

    private static func hashEmptyMessageBytes(
        cipherSuite: TLSCipherSuite
    ) -> OwnedBytes {
        let count = Self.hashByteCount(for: cipherSuite)
        var output = ContiguousArray<UInt8>(repeating: 0, count: count)
        var destination = output.mutableSpan
        do {
            switch cipherSuite {
            case .aes256GCM_SHA384:
                try SHA384.hash(ContiguousArray<UInt8>().span, into: &destination)
            case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                try SHA256.hash(ContiguousArray<UInt8>().span, into: &destination)
            }
        } catch {
            preconditionFailure("TLS hash output length is a compile-time invariant")
        }
        return OwnedBytes(consuming: output)
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }
}
