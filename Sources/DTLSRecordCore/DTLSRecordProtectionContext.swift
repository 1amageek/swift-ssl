/// A type-erased, immutable DTLS record protection context.
///
/// Concrete keyed AEAD values are captured once by provider-specific factories.
/// The sans-IO engine stores this non-generic owner so the Swift 6.4 normal WASM
/// runtime does not need to construct metadata for associated-type payloads inside
/// a cross-module generic record engine. The closures preserve typed failures and
/// static provider selection at construction; they perform no I/O or fallback.

public struct DTLSRecordProtectionContext: Sendable {
    private let sealOperation: @Sendable (
        _ plaintext: [UInt8],
        _ explicitNonce: [UInt8],
        _ aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8]
    private let openOperation: @Sendable (
        _ ciphertext: [UInt8],
        _ aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8]

    public init(
        seal: @escaping @Sendable (
            _ plaintext: [UInt8],
            _ explicitNonce: [UInt8],
            _ aad: [UInt8]
        ) throws(DTLSRecordProtectionError) -> [UInt8],
        open: @escaping @Sendable (
            _ ciphertext: [UInt8],
            _ aad: [UInt8]
        ) throws(DTLSRecordProtectionError) -> [UInt8]
    ) {
        self.sealOperation = seal
        self.openOperation = open
    }

    public func seal(
        plaintext: [UInt8],
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        try sealOperation(plaintext, explicitNonce, aad)
    }

    public func open(
        ciphertext: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        try openOperation(ciphertext, aad)
    }
}
