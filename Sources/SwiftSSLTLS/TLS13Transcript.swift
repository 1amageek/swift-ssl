import SwiftSSLCore
import SwiftSSLCrypto

/// Bounded transcript owner for TLS 1.3 handshake messages.
public struct TLS13Transcript: ~Copyable, Sendable {
    public static let defaultMaximumByteCount = 1 << 20

    private var storage: ContiguousArray<UInt8>
    public let maximumByteCount: Int

    public init(maximumByteCount: Int = Self.defaultMaximumByteCount) throws(TLS13HandshakeError) {
        guard maximumByteCount >= 0 else {
            throw .transcriptTooLong(limit: 0, attempted: maximumByteCount)
        }
        storage = []
        storage.reserveCapacity(Swift.min(maximumByteCount, 4 * 1024))
        self.maximumByteCount = maximumByteCount
    }

    public var byteCount: Int { storage.count }

    package borrowing func clone() -> TLS13Transcript {
        TLS13Transcript(
            storage: storage,
            maximumByteCount: maximumByteCount
        )
    }

    public mutating func append(_ message: Span<UInt8>) throws(TLS13HandshakeError) {
        let (attempted, overflow) = storage.count.addingReportingOverflow(message.count)
        guard !overflow, attempted <= maximumByteCount else {
            throw .transcriptTooLong(
                limit: maximumByteCount,
                attempted: overflow ? Int.max : attempted
            )
        }
        var index = 0
        while index < message.count {
            storage.append(message[index])
            index += 1
        }
    }

    public borrowing func digest(
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        let byteCount = cipherSuite == .aes256GCM_SHA384 ? 48 : 32
        var output = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
        do {
            try output.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
                var destination = MutableSpan(_unsafeStart: buffer.baseAddress!, count: byteCount)
                switch cipherSuite {
                case .aes256GCM_SHA384:
                    try SHA384.hash(storage.span, into: &destination)
                case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                    try SHA256.hash(storage.span, into: &destination)
                }
            }
        } catch {
            throw .cryptographicFailure
        }
        return OwnedBytes(consuming: output)
    }

    public borrowing func digest(
        appending message: Span<UInt8>,
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        var snapshot = try TLS13Transcript(
            maximumByteCount: maximumByteCount
        )
        try snapshot.append(storage.span)
        try snapshot.append(message)
        return try snapshot.digest(for: cipherSuite)
    }

    public mutating func replaceWithMessageHash(
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeError) {
        guard !storage.isEmpty else { throw .malformedMessage }
        let clientHelloHash = try digest(for: cipherSuite)
        try resetWithMessageHash(
            clientHelloHash.span,
            for: cipherSuite
        )
    }

    public mutating func resetWithMessageHash(
        _ clientHelloHash: Span<UInt8>,
        for cipherSuite: TLSCipherSuite
    ) throws(TLS13HandshakeError) {
        let expectedByteCount =
            cipherSuite == .aes256GCM_SHA384 ? 48 : 32
        guard clientHelloHash.count == expectedByteCount,
              maximumByteCount >= expectedByteCount + 4
        else {
            throw .malformedMessage
        }
        storage.removeAll(keepingCapacity: true)
        storage.append(TLS13HandshakeCodec.messageHashType)
        storage.append(0)
        storage.append(0)
        storage.append(UInt8(expectedByteCount))
        var index = 0
        while index < clientHelloHash.count {
            storage.append(clientHelloHash[index])
            index += 1
        }
    }

    private init(
        storage: ContiguousArray<UInt8>,
        maximumByteCount: Int
    ) {
        self.storage = storage
        self.maximumByteCount = maximumByteCount
    }
}
