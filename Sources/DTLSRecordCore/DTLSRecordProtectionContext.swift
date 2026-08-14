/// A type-erased, immutable DTLS record protection context.
///
/// Concrete keyed AEAD values are captured once by provider-specific factories.
/// The sans-IO engine stores this non-generic owner so the Swift 6.4 normal WASM
/// runtime does not need to construct metadata for associated-type payloads inside
/// a cross-module generic record engine. The closures preserve typed failures and
/// static provider selection at construction; they perform no I/O or fallback.

import NetworkingCore

public struct DTLSRecordProtectionContext: Sendable {
    private let recordOverhead: Int
    private let sealOperation: @Sendable (
        _ plaintext: Span<UInt8>,
        _ explicitNonce: [UInt8],
        _ aad: [UInt8],
        _ output: inout MutableSpan<UInt8>
    ) throws(DTLSRecordProtectionError) -> Void
    private let openOperation: @Sendable (
        _ ciphertext: Span<UInt8>,
        _ aad: [UInt8],
        _ output: inout MutableSpan<UInt8>
    ) throws(DTLSRecordProtectionError) -> Void

    public init(
        recordOverhead: Int,
        seal: @escaping @Sendable (
            _ plaintext: Span<UInt8>,
            _ explicitNonce: [UInt8],
            _ aad: [UInt8],
            _ output: inout MutableSpan<UInt8>
        ) throws(DTLSRecordProtectionError) -> Void,
        open: @escaping @Sendable (
            _ ciphertext: Span<UInt8>,
            _ aad: [UInt8],
            _ output: inout MutableSpan<UInt8>
        ) throws(DTLSRecordProtectionError) -> Void
    ) {
        precondition(recordOverhead > 0)
        self.recordOverhead = recordOverhead
        self.sealOperation = seal
        self.openOperation = open
    }

    public func seal(
        plaintext: Span<UInt8>,
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        let outputCount = try sealedByteCount(forPlaintextByteCount: plaintext.count)
        var output = [UInt8](repeating: 0, count: outputCount)
        try output.withUnsafeMutableBufferPointer { buffer throws(DTLSRecordProtectionError) in
            var outputSpan = MutableSpan(_unsafeElements: buffer)
            try seal(
                plaintext: plaintext,
                explicitNonce: explicitNonce,
                aad: aad,
                into: &outputSpan
            )
        }
        return output
    }

    /// Seals directly into caller-owned record-fragment storage.
    ///
    /// `output` must have exactly ``sealedByteCount(forPlaintextByteCount:)``
    /// elements. Its mutable borrow is scoped to this synchronous call and cannot
    /// escape through the stored operation.
    public func seal(
        plaintext: Span<UInt8>,
        explicitNonce: [UInt8],
        aad: [UInt8],
        into output: inout MutableSpan<UInt8>
    ) throws(DTLSRecordProtectionError) {
        let expected = try sealedByteCount(forPlaintextByteCount: plaintext.count)
        guard output.count == expected else {
            throw .invalidOutputLength(expected: expected, actual: output.count)
        }
        try sealOperation(plaintext, explicitNonce, aad, &output)
    }

    /// Returns the exact record-fragment size required for a plaintext length.
    public func sealedByteCount(
        forPlaintextByteCount plaintextByteCount: Int
    ) throws(DTLSRecordProtectionError) -> Int {
        guard plaintextByteCount >= 0 else {
            throw .invalidPlaintextLength(actual: plaintextByteCount)
        }
        let (outputCount, overflow) = plaintextByteCount.addingReportingOverflow(recordOverhead)
        guard !overflow else {
            throw .outputLengthOverflow(
                plaintextByteCount: plaintextByteCount,
                recordOverhead: recordOverhead
            )
        }
        return outputCount
    }

    public func open(
        ciphertext: Span<UInt8>,
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        guard ciphertext.count >= recordOverhead else {
            throw .ciphertextTooShort(minimum: recordOverhead, actual: ciphertext.count)
        }
        var output = [UInt8](repeating: 0, count: ciphertext.count - recordOverhead)
        try output.withUnsafeMutableBufferPointer { buffer throws(DTLSRecordProtectionError) in
            var outputSpan = MutableSpan(_unsafeElements: buffer)
            try openOperation(ciphertext, aad, &outputSpan)
        }
        return output
    }
}
