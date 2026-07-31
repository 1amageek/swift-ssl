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
}
