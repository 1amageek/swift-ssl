import SwiftSSLCore
import SwiftSSLCrypto

/// TLS 1.3 record protection for the three standardized AEAD cipher suites.
///
/// The protector owns the traffic key and IV. The sequence number is a
/// single-owner state value and is advanced only after a successful operation.
public struct TLS13RecordProtector: ~Copyable, Sendable {
    public static let maximumPlaintextByteCount = 16_384
    public static let maximumPaddingByteCount = 255
    public static let maximumCiphertextByteCount = 16_640
    public static let recordHeaderByteCount = 5

    public let cipherSuite: TLSCipherSuite

    private let key: SecretBytes
    private let iv: SecretBytes
    private var sequenceNumber: UInt64

    public init(
        cipherSuite: TLSCipherSuite,
        trafficSecret: Span<UInt8>
    ) throws(TLS13RecordError) {
        let hashByteCount = Self.hashByteCount(for: cipherSuite)
        guard trafficSecret.count == hashByteCount else {
            throw .invalidTrafficSecretLength(expected: hashByteCount, actual: trafficSecret.count)
        }
        let keyByteCount = Self.keyByteCount(for: cipherSuite)
        let derivedKey = try Self.deriveSecret(
            trafficSecret: trafficSecret,
            label: "key",
            outputByteCount: keyByteCount,
            cipherSuite: cipherSuite
        )
        let derivedIV = try Self.deriveSecret(
            trafficSecret: trafficSecret,
            label: "iv",
            outputByteCount: 12,
            cipherSuite: cipherSuite
        )
        key = derivedKey
        iv = derivedIV
        self.cipherSuite = cipherSuite
        sequenceNumber = 0
    }

    public var currentSequenceNumber: UInt64 {
        sequenceNumber
    }

    /// Seals one TLSInnerPlaintext into a complete TLSCiphertext record.
    /// The caller-provided output receives the five-byte outer header followed
    /// by ciphertext and tag. Input and output must not overlap.
    public mutating func seal(
        content: Span<UInt8>,
        contentType: TLS13ContentType,
        paddingByteCount: Int = 0,
        into output: inout MutableSpan<UInt8>
    ) throws(TLS13RecordError) {
        try Self.validateContent(content.count, paddingByteCount: paddingByteCount)
        guard sequenceNumber != UInt64.max else {
            throw .sequenceNumberExhausted
        }
        let innerByteCount = content.count + 1 + paddingByteCount
        let ciphertextByteCount = innerByteCount + Self.tagByteCount
        guard ciphertextByteCount <= Self.maximumCiphertextByteCount else {
            throw .recordTooLarge(limit: Self.maximumCiphertextByteCount, actual: ciphertextByteCount)
        }
        let recordByteCount = Self.recordHeaderByteCount + ciphertextByteCount
        guard output.count >= recordByteCount else {
            throw .outputTooSmall(required: recordByteCount, actual: output.count)
        }
        guard !Self.spansOverlap(content, output.span) else {
            throw .overlappingInputAndOutput
        }

        var nonce = Self.makeNonce(iv: iv, sequenceNumber: sequenceNumber)
        defer { Self.wipe(&nonce) }

        // Unsafe boundary invariants:
        // - output owns initialized UInt8 storage for the validated record range.
        // - The raw pointer is borrowed only for this synchronous closure.
        // - The input span cannot overlap output, checked before entering it.
        // - The plaintext and ciphertext spans are the same initialized region;
        //   the selected AEAD explicitly permits exact in-place operation.
        // - No pointer or span escapes and no Sendable boundary is crossed.
        var sealSucceeded = false
        output.withUnsafeMutableBytes { rawBytes in
                guard let baseAddress = rawBytes.baseAddress else {
                    return
                }
                let base = baseAddress.assumingMemoryBound(to: UInt8.self)
                base[0] = TLS13ContentType.applicationData.rawValue
                base[1] = 0x03
                base[2] = 0x03
                base[3] = UInt8(truncatingIfNeeded: ciphertextByteCount >> 8)
                base[4] = UInt8(truncatingIfNeeded: ciphertextByteCount)

                var index = 0
                while index < content.count {
                    base[Self.recordHeaderByteCount + index] = content[index]
                    index += 1
                }
                base[Self.recordHeaderByteCount + content.count] = contentType.rawValue
                index = 0
                while index < paddingByteCount {
                    base[Self.recordHeaderByteCount + content.count + 1 + index] = 0
                    index += 1
                }

                let plaintextPointer = UnsafeBufferPointer(
                    start: base.advanced(by: Self.recordHeaderByteCount),
                    count: innerByteCount
                )
                let plaintext = Span(_unsafeElements: plaintextPointer)
                let header = Span(
                    _unsafeElements: UnsafeBufferPointer(start: base, count: Self.recordHeaderByteCount)
                )
                var sealed = MutableSpan(
                    _unsafeStart: base.advanced(by: Self.recordHeaderByteCount),
                    count: ciphertextByteCount
                )
                key.withBorrowedBytes { keyBytes in
                    sealSucceeded = Self.withCipher(
                        cipherSuite: cipherSuite,
                        key: keyBytes,
                        plaintext: plaintext,
                        authenticatedData: header,
                        nonce: nonce.span,
                        into: &sealed
                    )
                }
        }
        guard sealSucceeded else {
            throw .invalidKeyMaterial
        }
        sequenceNumber &+= 1
    }

    /// Opens a complete TLSCiphertext record and copies the unpadded content
    /// into `output` only after authentication and inner-type validation.
    public mutating func open(
        record: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) throws(TLS13RecordError) -> TLS13ContentType {
        guard record.count >= Self.recordHeaderByteCount + Self.tagByteCount else {
            throw .malformedRecord
        }
        guard record[0] == TLS13ContentType.applicationData.rawValue else {
            throw .invalidOuterType(record[0])
        }
        let version = (UInt16(record[1]) << 8) | UInt16(record[2])
        guard version == 0x0303 else {
            throw .invalidLegacyVersion(version)
        }
        let ciphertextByteCount = (Int(record[3]) << 8) | Int(record[4])
        guard ciphertextByteCount == record.count - Self.recordHeaderByteCount else {
            throw .malformedRecord
        }
        guard ciphertextByteCount >= Self.tagByteCount + 1 else {
            throw .malformedRecord
        }
        let innerByteCount = ciphertextByteCount - Self.tagByteCount
        guard innerByteCount <= Self.maximumPlaintextByteCount + 1 + Self.maximumPaddingByteCount else {
            throw .recordTooLarge(
                limit: Self.maximumPlaintextByteCount + 1 + Self.maximumPaddingByteCount + Self.tagByteCount,
                actual: ciphertextByteCount
            )
        }
        guard ciphertextByteCount <= Self.maximumCiphertextByteCount else {
            throw .recordTooLarge(limit: Self.maximumCiphertextByteCount, actual: ciphertextByteCount)
        }
        guard sequenceNumber != UInt64.max else {
            throw .sequenceNumberExhausted
        }
        let ciphertext = record.extracting(Self.recordHeaderByteCount..<record.count)
        let authenticatedData = record.extracting(0..<Self.recordHeaderByteCount)
        var plaintext = ContiguousArray<UInt8>(repeating: 0, count: innerByteCount)
        defer { Self.wipe(&plaintext) }
        var nonce = Self.makeNonce(iv: iv, sequenceNumber: sequenceNumber)
        defer { Self.wipe(&nonce) }

        var openSucceeded = false
        plaintext.withUnsafeMutableBufferPointer { buffer in
                guard let baseAddress = buffer.baseAddress else {
                    return
                }
                var destination = MutableSpan(_unsafeStart: baseAddress, count: innerByteCount)
                key.withBorrowedBytes { keyBytes in
                    openSucceeded = Self.withCipherOpen(
                        cipherSuite: cipherSuite,
                        key: keyBytes,
                        ciphertextAndTag: ciphertext,
                        authenticatedData: authenticatedData,
                        nonce: nonce.span,
                        into: &destination
                    )
                }
            }
        guard openSucceeded else {
            throw .authenticationFailed
        }

        var typeIndex = plaintext.count - 1
        while typeIndex >= 0, plaintext[typeIndex] == 0 {
            typeIndex -= 1
        }
        guard typeIndex >= 0, let contentType = TLS13ContentType(rawValue: plaintext[typeIndex]) else {
            throw .malformedRecord
        }
        let contentByteCount = typeIndex
        guard output.count >= contentByteCount else {
            throw .outputTooSmall(required: contentByteCount, actual: output.count)
        }
        var index = 0
        while index < contentByteCount {
            output[index] = plaintext[index]
            index += 1
        }
        sequenceNumber &+= 1
        return contentType
    }

    private static let tagByteCount = 16

    private static func validateContent(
        _ contentByteCount: Int,
        paddingByteCount: Int
    ) throws(TLS13RecordError) {
        guard contentByteCount <= Self.maximumPlaintextByteCount else {
            throw .invalidContentLength(actual: contentByteCount)
        }
        guard paddingByteCount >= 0, paddingByteCount <= Self.maximumPaddingByteCount else {
            throw .invalidPaddingLength(actual: paddingByteCount)
        }
    }

    private static func hashByteCount(for suite: TLSCipherSuite) -> Int {
        suite == .aes256GCM_SHA384 ? 48 : 32
    }

    private static func keyByteCount(for suite: TLSCipherSuite) -> Int {
        switch suite {
        case .aes128GCM_SHA256:
            return 16
        case .aes256GCM_SHA384, .chacha20Poly1305_SHA256:
            return 32
        }
    }

    private static func deriveSecret(
        trafficSecret: Span<UInt8>,
        label: String,
        outputByteCount: Int,
        cipherSuite: TLSCipherSuite
    ) throws(TLS13RecordError) -> SecretBytes {
        var info = ContiguousArray<UInt8>()
        info.reserveCapacity(2 + 1 + 6 + label.utf8.count + 1)
        info.append(UInt8(truncatingIfNeeded: outputByteCount >> 8))
        info.append(UInt8(truncatingIfNeeded: outputByteCount))
        info.append(UInt8(6 + label.utf8.count))
        info.append(contentsOf: "tls13 ".utf8)
        info.append(contentsOf: label.utf8)
        info.append(0)

        var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
        defer {
            output.withUnsafeMutableBufferPointer { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
            }
        }
        do {
            try output.withUnsafeMutableBufferPointer { buffer throws(HKDFError) in
                // The derived output sizes are fixed and strictly positive.
                let baseAddress = buffer.baseAddress!
                var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
                switch cipherSuite {
                case .aes256GCM_SHA384:
                    try HKDFSHA384.expand(
                        pseudorandomKey: trafficSecret,
                        info: info.span,
                        into: &destination
                    )
                case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
                    try HKDFSHA256.expand(
                        pseudorandomKey: trafficSecret,
                        info: info.span,
                        into: &destination
                    )
                }
            }
        } catch {
            throw .invalidKeyMaterial
        }
        do {
            return try SecretBytes(copying: output.span)
        } catch {
            throw .invalidKeyMaterial
        }
    }

    private static func makeNonce(
        iv: borrowing SecretBytes,
        sequenceNumber: UInt64
    ) -> ContiguousArray<UInt8> {
        var nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
        iv.withBorrowedBytes { bytes in
            var index = 0
            while index < 12 {
                nonce[index] = bytes[index]
                index += 1
            }
        }
        var index = 0
        while index < 8 {
            let shift = UInt64((7 - index) * 8)
            nonce[4 + index] ^= UInt8(truncatingIfNeeded: sequenceNumber >> shift)
            index += 1
        }
        return nonce
    }

    private static func withCipher(
        cipherSuite: TLSCipherSuite,
        key: Span<UInt8>,
        plaintext: Span<UInt8>,
        authenticatedData: Span<UInt8>,
        nonce: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) -> Bool {
        switch cipherSuite {
            case .aes128GCM_SHA256:
                do {
                    var cipher = try AESGCM(key: key)
                    try cipher.seal(plaintext: plaintext, authenticatedData: authenticatedData, nonce: nonce, into: &output)
                    return true
                } catch {
                    return false
                }
            case .aes256GCM_SHA384:
                do {
                    var cipher = try AESGCM(key: key)
                    try cipher.seal(plaintext: plaintext, authenticatedData: authenticatedData, nonce: nonce, into: &output)
                    return true
                } catch {
                    return false
                }
            case .chacha20Poly1305_SHA256:
                do {
                    var cipher = try ChaCha20Poly1305(key: key)
                    try cipher.seal(plaintext: plaintext, authenticatedData: authenticatedData, nonce: nonce, into: &output)
                    return true
                } catch {
                    return false
                }
        }
    }

    private static func withCipherOpen(
        cipherSuite: TLSCipherSuite,
        key: Span<UInt8>,
        ciphertextAndTag: Span<UInt8>,
        authenticatedData: Span<UInt8>,
        nonce: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) -> Bool {
        switch cipherSuite {
        case .aes128GCM_SHA256, .aes256GCM_SHA384:
            do {
                var cipher = try AESGCM(key: key)
                try cipher.open(ciphertextAndTag: ciphertextAndTag, authenticatedData: authenticatedData, nonce: nonce, into: &output)
                return true
            } catch {
                return false
            }
        case .chacha20Poly1305_SHA256:
            do {
                var cipher = try ChaCha20Poly1305(key: key)
                try cipher.open(ciphertextAndTag: ciphertextAndTag, authenticatedData: authenticatedData, nonce: nonce, into: &output)
                return true
            } catch {
                return false
            }
        }
    }

    private static func spansOverlap(
        _ first: Span<UInt8>,
        _ second: Span<UInt8>
    ) -> Bool {
        guard !first.isEmpty, !second.isEmpty else { return false }
        return first.withUnsafeBufferPointer { firstBuffer in
            second.withUnsafeBufferPointer { secondBuffer in
                guard let firstBase = firstBuffer.baseAddress,
                      let secondBase = secondBuffer.baseAddress else { return false }
                let firstStart = UInt(bitPattern: firstBase)
                let secondStart = UInt(bitPattern: secondBase)
                let (firstEnd, firstOverflow) = firstStart.addingReportingOverflow(UInt(firstBuffer.count))
                let (secondEnd, secondOverflow) = secondStart.addingReportingOverflow(UInt(secondBuffer.count))
                guard !firstOverflow, !secondOverflow else { return true }
                return firstStart < secondEnd && secondStart < firstEnd
            }
        }
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }
}
