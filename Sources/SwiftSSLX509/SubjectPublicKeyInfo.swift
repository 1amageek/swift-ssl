import SwiftSSLCore
import SwiftSSLASN1

public struct SubjectPublicKeyInfo: Sendable, Hashable {
    public let algorithmIdentifier: DERAlgorithmIdentifier
    public let algorithm: PublicKeyAlgorithm

    private let der: OwnedBytes
    private let keyRange: ByteRange

    /// Whether this key is a canonical Ed25519 SubjectPublicKeyInfo.
    public var isEd25519: Bool {
        algorithm == .ed25519 && algorithmIdentifier.parameters == .absent
    }

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = SubjectPublicKeyInfo.defaultParsingLimits
    ) throws(SubjectPublicKeyInfoError) {
        let owned = OwnedBytes(copying: encodedDER)
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: owned.count)
        } catch {
            throw .resourceLimit(error)
        }

        var cursor = DERCursor(owned.span)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard root.tag == sequenceTag else {
            throw .invalidStructure
        }

        var body = DERCursor(
            root.contentBytes,
            baseOffset: root.encodedOffset + root.headerByteCount
        )
        let algorithmElement: DERElementView
        let keyElement: DERElementView
        do {
            algorithmElement = try body.readElement(using: &budget)
            keyElement = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        let algorithmIdentifier: DERAlgorithmIdentifier
        do {
            algorithmIdentifier = try DERAlgorithmIdentifier.parse(
                from: algorithmElement,
                using: &budget
            )
        } catch let error {
            throw .algorithm(error)
        }
        let keyBits: DERBitString
        do {
            keyBits = try DERPrimitiveCodec.decodeBitString(from: keyElement)
        } catch let error {
            throw .value(error)
        }
        guard keyBits.unusedBitCount == 0 else {
            throw .invalidKeyBitString
        }
        let keyOffset = keyElement.encodedOffset + keyElement.headerByteCount + 1
        let keyRange: ByteRange
        do {
            keyRange = try ByteRange(offset: keyOffset, count: keyBits.bytes.count)
        } catch {
            throw .invalidRange(error)
        }

        self.der = owned
        self.keyRange = keyRange
        self.algorithmIdentifier = algorithmIdentifier
        self.algorithm = Self.mapAlgorithm(algorithmIdentifier)
    }

    public var publicKeyByteCount: Int {
        keyRange.count
    }

    public borrowing func withPublicKeyBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: keyRange)
        } catch {
            preconditionFailure("SubjectPublicKeyInfo stores a validated key range")
        }
        return try body(bytes)
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
            preconditionFailure("SubjectPublicKeyInfo limits are compile-time constants")
        }
    }()

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
