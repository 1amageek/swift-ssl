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
        guard ecdheSharedSecret.count == hashByteCount else {
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

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }
}
