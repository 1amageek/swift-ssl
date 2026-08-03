import SSLCore
import SSLCrypto

/// RFC 9001 version-1 Initial packet secrets and packet-protection material.
///
/// Initial keys are always AES-128-GCM/HP material derived with SHA-256. The
/// value owns every derived secret and exposes only scoped immutable borrows;
/// packet construction and header protection remain transport responsibilities.
public struct QUICInitialSecrets: ~Copyable, Sendable {
    public static let maximumDestinationConnectionIDByteCount = 20
    public static let keyByteCount = 16
    public static let ivByteCount = 12
    public static let headerProtectionKeyByteCount = 16

    private static let initialSalt = ContiguousArray<UInt8>([
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3,
        0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD,
        0xCC, 0xBB, 0x7F, 0x0A,
    ])

    private let clientInitialSecret: SecretBytes
    private let serverInitialSecret: SecretBytes
    private let clientKey: SecretBytes
    private let serverKey: SecretBytes
    private let clientIV: SecretBytes
    private let serverIV: SecretBytes
    private let clientHeaderProtectionKey: SecretBytes
    private let serverHeaderProtectionKey: SecretBytes

    public init(
        destinationConnectionID: Span<UInt8>
    ) throws(QUICInitialSecretsError) {
        guard destinationConnectionID.count <= Self.maximumDestinationConnectionIDByteCount else {
            throw .invalidDestinationConnectionIDLength(actual: destinationConnectionID.count)
        }
        do {
            let initialSecret = try Self.extract(
                salt: Self.initialSalt.span,
                input: destinationConnectionID
            )
            let clientInitialSecret = try Self.derive(
                secret: initialSecret,
                label: "client in",
                outputByteCount: SHA256.digestByteCount
            )
            let serverInitialSecret = try Self.derive(
                secret: initialSecret,
                label: "server in",
                outputByteCount: SHA256.digestByteCount
            )
            let clientKey = try Self.derive(
                secret: clientInitialSecret,
                label: "quic key",
                outputByteCount: Self.keyByteCount
            )
            let serverKey = try Self.derive(
                secret: serverInitialSecret,
                label: "quic key",
                outputByteCount: Self.keyByteCount
            )
            let clientIV = try Self.derive(
                secret: clientInitialSecret,
                label: "quic iv",
                outputByteCount: Self.ivByteCount
            )
            let serverIV = try Self.derive(
                secret: serverInitialSecret,
                label: "quic iv",
                outputByteCount: Self.ivByteCount
            )
            let clientHeaderProtectionKey = try Self.derive(
                secret: clientInitialSecret,
                label: "quic hp",
                outputByteCount: Self.headerProtectionKeyByteCount
            )
            let serverHeaderProtectionKey = try Self.derive(
                secret: serverInitialSecret,
                label: "quic hp",
                outputByteCount: Self.headerProtectionKeyByteCount
            )
            self.clientInitialSecret = consume clientInitialSecret
            self.serverInitialSecret = consume serverInitialSecret
            self.clientKey = consume clientKey
            self.serverKey = consume serverKey
            self.clientIV = consume clientIV
            self.serverIV = consume serverIV
            self.clientHeaderProtectionKey = consume clientHeaderProtectionKey
            self.serverHeaderProtectionKey = consume serverHeaderProtectionKey
        } catch let error as QUICInitialSecretsError {
            throw error
        } catch {
            throw .secretMemoryFailure
        }
    }

    public borrowing func withClientInitialSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientInitialSecret.withBorrowedBytes(body)
    }

    public borrowing func withServerInitialSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverInitialSecret.withBorrowedBytes(body)
    }

    public borrowing func withClientKey<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientKey.withBorrowedBytes(body)
    }

    public borrowing func withServerKey<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverKey.withBorrowedBytes(body)
    }

    public borrowing func withClientIV<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientIV.withBorrowedBytes(body)
    }

    public borrowing func withServerIV<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverIV.withBorrowedBytes(body)
    }

    public borrowing func withClientHeaderProtectionKey<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientHeaderProtectionKey.withBorrowedBytes(body)
    }

    public borrowing func withServerHeaderProtectionKey<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverHeaderProtectionKey.withBorrowedBytes(body)
    }

    private static func extract(
        salt: Span<UInt8>,
        input: Span<UInt8>
    ) throws(QUICInitialSecretsError) -> SecretBytes {
        var output = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
        defer { wipe(&output) }
        do {
            var destination = output.mutableSpan
            try HKDFSHA256.extract(
                inputKeyMaterial: input,
                salt: salt,
                into: &destination
            )
            return try SecretBytes(copying: output.span)
        } catch let error as HKDFError {
            throw .hkdfFailure(error)
        } catch {
            throw .secretMemoryFailure
        }
    }

    private static func derive(
        secret: borrowing SecretBytes,
        label: String,
        outputByteCount: Int
    ) throws(QUICInitialSecretsError) -> SecretBytes {
        var info = ContiguousArray<UInt8>()
        // QUIC invokes TLS 1.3 HKDF-Expand-Label; the function itself adds
        // the mandatory "tls13 " label prefix before the caller's label.
        let labelBytes = Array("tls13 ".utf8) + Array(label.utf8)
        info.reserveCapacity(2 + 1 + labelBytes.count + 1)
        info.append(UInt8(truncatingIfNeeded: outputByteCount >> 8))
        info.append(UInt8(truncatingIfNeeded: outputByteCount))
        info.append(UInt8(truncatingIfNeeded: labelBytes.count))
        info.append(contentsOf: labelBytes)
        info.append(0)

        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        defer { wipe(&output) }
        do {
            try secret.withBorrowedBytes { secretBytes in
                var destination = output.mutableSpan
                try HKDFSHA256.expand(
                    pseudorandomKey: secretBytes,
                    info: info.span,
                    into: &destination
                )
            }
            return try SecretBytes(copying: output.span)
        } catch let error as HKDFError {
            throw .hkdfFailure(error)
        } catch {
            throw .secretMemoryFailure
        }
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }
}
