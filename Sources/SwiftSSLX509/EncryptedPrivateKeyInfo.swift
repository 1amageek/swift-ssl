import SwiftSSLCore
import SwiftSSLASN1

/// A strict RFC 5958 EncryptedPrivateKeyInfo using the modern project profile.
///
/// The accepted profile is PBES2 with PBKDF2-HMAC-SHA256 and AES-256-GCM.
/// Legacy PBKDF2-HMAC-SHA1 and unauthenticated CBC encryption are rejected.
public struct EncryptedPrivateKeyInfo: Sendable {
    public static let saltByteCount = 16
    public static let nonceByteCount = 12
    public static let authenticationTagByteCount = 16
    public static let derivedKeyByteCount = 32

    public let iterationCount: UInt32

    private let der: OwnedBytes
    private let saltRange: ByteRange
    private let nonceRange: ByteRange
    private let encryptedDataRange: ByteRange

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = EncryptedPrivateKeyInfo.defaultParsingLimits
    ) throws {
        let owned = OwnedBytes(copying: encodedDER)
        try self.init(consumingDER: owned, limits: limits)
    }

    init(
        consumingDER der: consuming OwnedBytes,
        limits: ParsingLimits = EncryptedPrivateKeyInfo.defaultParsingLimits
    ) throws {
        let parsed = try Self.parse(der.span, limits: limits)
        iterationCount = parsed.iterationCount
        saltRange = parsed.saltRange
        nonceRange = parsed.nonceRange
        encryptedDataRange = parsed.encryptedDataRange
        self.der = der
    }

    public var encryptedDataByteCount: Int {
        encryptedDataRange.count
    }

    public var derByteCount: Int {
        der.count
    }

    public var plaintextByteCount: Int {
        encryptedDataRange.count - Self.authenticationTagByteCount
    }

    public borrowing func withDERBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes(body)
    }

    public borrowing func withSaltBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try withBytes(in: saltRange, body)
    }

    public borrowing func withNonceBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try withBytes(in: nonceRange, body)
    }

    public borrowing func withEncryptedDataBytes<
        Result: ~Copyable,
        Failure: Error
    >(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try withBytes(in: encryptedDataRange, body)
    }

    borrowing func withCryptographicInputs<
        Result: ~Copyable,
        Failure: Error
    >(
        _ body: (
            Span<UInt8>,
            Span<UInt8>,
            Span<UInt8>
        ) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes {
            (bytes: Span<UInt8>) throws(Failure) -> Result in
            try body(
                bytes.extracting(saltRange.offset..<saltRange.endOffset),
                bytes.extracting(nonceRange.offset..<nonceRange.endOffset),
                bytes.extracting(
                    encryptedDataRange.offset..<encryptedDataRange.endOffset
                )
            )
        }
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 16 * 1024 * 1024,
                maximumNestingDepth: 16,
                maximumElementCount: 64,
                maximumExtensionCount: 1,
                maximumOIDBytes: 128,
                maximumStringBytes: 4 * 1024
            )
        } catch {
            preconditionFailure(
                "EncryptedPrivateKeyInfo limits are compile-time constants"
            )
        }
    }()

    private borrowing func withBytes<Result: ~Copyable, Failure: Error>(
        in range: ByteRange,
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes {
            (bytes: Span<UInt8>) throws(Failure) -> Result in
            try body(bytes.extracting(range.offset..<range.endOffset))
        }
    }

    private static func parse(
        _ encodedDER: Span<UInt8>,
        limits: ParsingLimits
    ) throws -> Parsed {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: encodedDER.count
            )
        } catch let error as ResourceLimitError {
            throw EncryptedPrivateKeyInfoError.resourceLimit(error)
        }

        var cursor = DERCursor(encodedDER)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard root.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        var body = DERCursor(
            root.contentBytes,
            baseOffset: root.encodedOffset + root.headerByteCount
        )
        let algorithm: DERElementView
        let encryptedData: DERElementView
        do {
            algorithm = try body.readElement(using: &budget)
            encryptedData = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard algorithm.tag == Self.sequenceTag,
              encryptedData.tag == Self.octetStringTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard encryptedData.contentBytes.count >= Self.authenticationTagByteCount else {
            throw EncryptedPrivateKeyInfoError.encryptedDataTooShort(
                minimum: Self.authenticationTagByteCount,
                actual: encryptedData.contentBytes.count
            )
        }

        let profile = try Self.parseEncryptionAlgorithm(
            algorithm,
            budget: &budget
        )
        let encryptedDataRange = try Self.contentRange(encryptedData)
        return Parsed(
            iterationCount: profile.iterationCount,
            saltRange: profile.saltRange,
            nonceRange: profile.nonceRange,
            encryptedDataRange: encryptedDataRange
        )
    }

    private static func parseEncryptionAlgorithm(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws -> Profile {
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let oidElement: DERElementView
        let parameters: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
            parameters = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard try Self.decodeOID(oidElement, budget: &budget) == Self.pbes2OID else {
            throw EncryptedPrivateKeyInfoError.unsupportedEncryptionAlgorithm
        }
        guard parameters.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        var parametersBody = DERCursor(
            parameters.contentBytes,
            baseOffset: parameters.encodedOffset + parameters.headerByteCount
        )
        let keyDerivation: DERElementView
        let encryptionScheme: DERElementView
        do {
            keyDerivation = try parametersBody.readElement(using: &budget)
            encryptionScheme = try parametersBody.readElement(using: &budget)
            try parametersBody.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard keyDerivation.tag == Self.sequenceTag,
              encryptionScheme.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        let keyParameters = try Self.parseKeyDerivation(
            keyDerivation,
            budget: &budget
        )
        let nonceRange = try Self.parseEncryptionScheme(
            encryptionScheme,
            budget: &budget
        )
        return Profile(
            iterationCount: keyParameters.iterationCount,
            saltRange: keyParameters.saltRange,
            nonceRange: nonceRange
        )
    }

    private static func parseKeyDerivation(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws -> KeyParameters {
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let oidElement: DERElementView
        let parameters: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
            parameters = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard try Self.decodeOID(oidElement, budget: &budget) == Self.pbkdf2OID else {
            throw EncryptedPrivateKeyInfoError.unsupportedKeyDerivationFunction
        }
        guard parameters.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        var parameterBody = DERCursor(
            parameters.contentBytes,
            baseOffset: parameters.encodedOffset + parameters.headerByteCount
        )
        let salt: DERElementView
        let iterations: DERElementView
        var next: DERElementView
        do {
            salt = try parameterBody.readElement(using: &budget)
            iterations = try parameterBody.readElement(using: &budget)
            next = try parameterBody.readElement(using: &budget)
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard salt.tag == Self.octetStringTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard salt.contentBytes.count == Self.saltByteCount else {
            throw EncryptedPrivateKeyInfoError.invalidSaltLength(
                expected: Self.saltByteCount,
                actual: salt.contentBytes.count
            )
        }

        let iterationValue = try Self.decodePositiveInteger(iterations)
        guard iterationValue > 0, iterationValue <= UInt64(UInt32.max) else {
            throw EncryptedPrivateKeyInfoError.invalidIterationCount(iterationValue)
        }

        if next.tag == Self.integerTag {
            let keyLength = try Self.decodePositiveInteger(next)
            guard keyLength == UInt64(Self.derivedKeyByteCount) else {
                throw EncryptedPrivateKeyInfoError.invalidDerivedKeyLength(keyLength)
            }
            do {
                next = try parameterBody.readElement(using: &budget)
            } catch let error as DERError {
                throw EncryptedPrivateKeyInfoError.der(error)
            } catch {
                throw EncryptedPrivateKeyInfoError.invalidStructure
            }
        }
        try Self.requireHMACSHA256(next, budget: &budget)
        do {
            try parameterBody.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        return KeyParameters(
            iterationCount: UInt32(iterationValue),
            saltRange: try Self.contentRange(salt)
        )
    }

    private static func requireHMACSHA256(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws {
        guard element.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let oidElement: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard try Self.decodeOID(oidElement, budget: &budget) == Self.hmacSHA256OID else {
            throw EncryptedPrivateKeyInfoError.unsupportedPseudorandomFunction
        }
        if !body.isAtEnd {
            let parameters: DERElementView
            do {
                parameters = try body.readElement(using: &budget)
                try body.requireFullyConsumed()
            } catch let error as DERError {
                throw EncryptedPrivateKeyInfoError.der(error)
            } catch {
                throw EncryptedPrivateKeyInfoError.invalidStructure
            }
            guard parameters.tag == Self.nullTag,
                  parameters.contentBytes.isEmpty else {
                throw EncryptedPrivateKeyInfoError.invalidStructure
            }
        }
    }

    private static func parseEncryptionScheme(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws -> ByteRange {
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let oidElement: DERElementView
        let parameters: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
            parameters = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard try Self.decodeOID(oidElement, budget: &budget) == Self.aes256GCMOID else {
            throw EncryptedPrivateKeyInfoError.unsupportedEncryptionAlgorithm
        }
        guard parameters.tag == Self.sequenceTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }

        var parameterBody = DERCursor(
            parameters.contentBytes,
            baseOffset: parameters.encodedOffset + parameters.headerByteCount
        )
        let nonce: DERElementView
        let tagLength: DERElementView
        do {
            nonce = try parameterBody.readElement(using: &budget)
            tagLength = try parameterBody.readElement(using: &budget)
            try parameterBody.requireFullyConsumed()
        } catch let error as DERError {
            throw EncryptedPrivateKeyInfoError.der(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard nonce.tag == Self.octetStringTag else {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
        guard nonce.contentBytes.count == Self.nonceByteCount else {
            throw EncryptedPrivateKeyInfoError.invalidNonceLength(
                expected: Self.nonceByteCount,
                actual: nonce.contentBytes.count
            )
        }
        let tagLengthValue = try Self.decodePositiveInteger(tagLength)
        guard tagLengthValue == UInt64(Self.authenticationTagByteCount) else {
            throw EncryptedPrivateKeyInfoError.invalidAuthenticationTagLength(
                tagLengthValue
            )
        }
        return try Self.contentRange(nonce)
    }

    private static func decodeOID(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws -> ContiguousArray<UInt64> {
        do {
            try budget.requireOIDByteCount(element.contentBytes.count)
            return try DERPrimitiveCodec.decodeObjectIdentifier(from: element)
        } catch let error as ResourceLimitError {
            throw EncryptedPrivateKeyInfoError.resourceLimit(error)
        } catch let error as DERValueError {
            throw EncryptedPrivateKeyInfoError.value(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
    }

    private static func decodePositiveInteger(
        _ element: DERElementView
    ) throws -> UInt64 {
        do {
            return try DERPrimitiveCodec.decodePositiveInteger(from: element)
        } catch let error as DERValueError {
            throw EncryptedPrivateKeyInfoError.value(error)
        } catch {
            throw EncryptedPrivateKeyInfoError.invalidStructure
        }
    }

    private static func contentRange(
        _ element: DERElementView
    ) throws -> ByteRange {
        do {
            return try ByteRange(
                offset: element.encodedOffset + element.headerByteCount,
                count: element.contentBytes.count
            )
        } catch let error as ByteError {
            throw EncryptedPrivateKeyInfoError.invalidRange(error)
        }
    }

    private struct Parsed {
        let iterationCount: UInt32
        let saltRange: ByteRange
        let nonceRange: ByteRange
        let encryptedDataRange: ByteRange
    }

    private struct Profile {
        let iterationCount: UInt32
        let saltRange: ByteRange
        let nonceRange: ByteRange
    }

    private struct KeyParameters {
        let iterationCount: UInt32
        let saltRange: ByteRange
    }

    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let octetStringTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 4
    )
    private static let integerTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 2
    )
    private static let nullTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 5
    )

    static let pbes2OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 5, 13,
    ]
    static let pbkdf2OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 5, 12,
    ]
    static let hmacSHA256OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 2, 9,
    ]
    static let aes256GCMOID: ContiguousArray<UInt64> = [
        2, 16, 840, 1, 101, 3, 4, 1, 46,
    ]
}
