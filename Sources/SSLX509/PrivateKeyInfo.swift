import SSLCore
import SSLASN1

/// A uniquely owned PKCS #8 private-key document.
///
/// The complete DER document is secret because it contains private-key
/// material. It therefore remains in wiped storage and is exposed only through
/// synchronous scoped borrows.
public struct PrivateKeyInfo: ~Copyable, Sendable {
    public let version: UInt64
    public let algorithmIdentifier: DERAlgorithmIdentifier
    public let algorithm: PublicKeyAlgorithm

    private let der: SecretBytes
    private let privateKeyRange: ByteRange

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = PrivateKeyInfo.defaultParsingLimits
    ) throws {
        let secretDER: SecretBytes
        do {
            secretDER = try SecretBytes(copying: encodedDER)
        } catch let error as SecretMemoryError {
            throw PrivateKeyInfoError.memoryFailure(error)
        }
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: encodedDER.count)
        } catch {
            throw PrivateKeyInfoError.resourceLimit(error)
        }

        var cursor = DERCursor(encodedDER)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error as DERError {
            throw PrivateKeyInfoError.der(error)
        } catch {
            throw PrivateKeyInfoError.invalidStructure
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard root.tag == sequenceTag else {
            throw PrivateKeyInfoError.invalidStructure
        }
        var body = DERCursor(
            root.contentBytes,
            baseOffset: root.encodedOffset + root.headerByteCount
        )
        let versionElement: DERElementView
        let algorithmElement: DERElementView
        let privateKeyElement: DERElementView
        do {
            versionElement = try body.readElement(using: &budget)
            algorithmElement = try body.readElement(using: &budget)
            privateKeyElement = try body.readElement(using: &budget)
        } catch let error as DERError {
            throw PrivateKeyInfoError.der(error)
        } catch {
            throw PrivateKeyInfoError.invalidStructure
        }

        let version: UInt64
        do {
            version = try DERPrimitiveCodec.decodePositiveInteger(from: versionElement)
        } catch let error as DERValueError {
            throw PrivateKeyInfoError.value(error)
        } catch {
            throw PrivateKeyInfoError.invalidStructure
        }
        guard version == 0 || version == 1 else {
            throw PrivateKeyInfoError.invalidVersion(version)
        }

        let algorithmIdentifier: DERAlgorithmIdentifier
        do {
            algorithmIdentifier = try DERAlgorithmIdentifier.parse(
                from: algorithmElement,
                using: &budget
            )
        } catch let error as DERAlgorithmIdentifierError {
            throw PrivateKeyInfoError.algorithm(error)
        } catch {
            throw PrivateKeyInfoError.invalidStructure
        }

        let octetTag = DERTag(tagClass: .universal, isConstructed: false, number: 4)
        guard privateKeyElement.tag == octetTag else {
            throw PrivateKeyInfoError.invalidStructure
        }
        let privateKeyRange: ByteRange
        do {
            privateKeyRange = try ByteRange(
                offset: privateKeyElement.encodedOffset + privateKeyElement.headerByteCount,
                count: privateKeyElement.contentBytes.count
            )
        } catch let error as ByteError {
            throw PrivateKeyInfoError.invalidRange(error)
        }

        var sawAttributes = false
        var sawPublicKey = false
        while !body.isAtEnd {
            let optionalElement: DERElementView
            do {
                optionalElement = try body.readElement(using: &budget)
            } catch let error as DERError {
                throw PrivateKeyInfoError.der(error)
            } catch {
                throw PrivateKeyInfoError.invalidStructure
            }
            switch (optionalElement.tag.tagClass, optionalElement.tag.isConstructed, optionalElement.tag.number) {
            case (.contextSpecific, true, 0):
                guard !sawAttributes else {
                    throw PrivateKeyInfoError.invalidStructure
                }
                sawAttributes = true
            case (.contextSpecific, false, 1):
                guard !sawPublicKey else {
                    throw PrivateKeyInfoError.invalidStructure
                }
                guard Self.validImplicitBitString(optionalElement.contentBytes) else {
                    throw PrivateKeyInfoError.invalidPublicKeyField
                }
                sawPublicKey = true
            default:
                throw PrivateKeyInfoError.invalidStructure
            }
        }
        guard version == (sawPublicKey ? 1 : 0) else {
            throw PrivateKeyInfoError.invalidVersion(version)
        }

        self.version = version
        self.algorithmIdentifier = algorithmIdentifier
        self.algorithm = Self.mapAlgorithm(algorithmIdentifier)
        der = secretDER
        self.privateKeyRange = privateKeyRange
    }

    public var privateKeyByteCount: Int {
        privateKeyRange.count
    }

    public var derByteCount: Int {
        der.count
    }

    public borrowing func withPrivateKeyBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes {
            (bytes: Span<UInt8>) throws(Failure) -> Result in
            try body(
                bytes.extracting(
                    privateKeyRange.offset..<privateKeyRange.endOffset
                )
            )
        }
    }

    public borrowing func withDERBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes(body)
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 16 * 1024 * 1024,
                maximumNestingDepth: 16,
                maximumElementCount: 128,
                maximumExtensionCount: 32,
                maximumOIDBytes: 128,
                maximumStringBytes: 4 * 1024
            )
        } catch {
            preconditionFailure("PrivateKeyInfo limits are compile-time constants")
        }
    }()

    private static func validImplicitBitString(_ content: Span<UInt8>) -> Bool {
        guard !content.isEmpty, content[0] <= 7 else {
            return false
        }
        let payloadCount = content.count - 1
        if payloadCount == 0 {
            return content[0] == 0
        }
        guard content[0] != 0 else {
            return true
        }
        let last = content[content.count - 1]
        let mask = UInt8((1 << content[0]) - 1)
        return (last & mask) == 0
    }

    private static func mapAlgorithm(
        _ identifier: DERAlgorithmIdentifier
    ) -> PublicKeyAlgorithm {
        switch Array(identifier.objectIdentifier) {
        case [1, 3, 101, 110]:
            return .x25519
        case [1, 3, 101, 112]:
            return .ed25519
        case [1, 2, 840, 113549, 1, 1, 1]:
            return .rsaEncryption
        case [1, 2, 840, 10045, 2, 1]:
            guard case let .objectIdentifier(curveOID) = identifier.parameters else {
                return .unknown(objectIdentifier: identifier.objectIdentifier)
            }
            return .ecPublicKey(curve: mapCurve(curveOID))
        default:
            return .unknown(objectIdentifier: identifier.objectIdentifier)
        }
    }

    private static func mapCurve(_ oid: ContiguousArray<UInt64>) -> NamedCurve {
        switch Array(oid) {
        case [1, 2, 840, 10045, 3, 1, 7]:
            .prime256v1
        case [1, 3, 132, 0, 34]:
            .secp384r1
        case [1, 3, 132, 0, 35]:
            .secp521r1
        default:
            .unknown(objectIdentifier: oid)
        }
    }
}
