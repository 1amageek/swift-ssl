import SwiftSSLCore
import SwiftSSLASN1

public struct PrivateKeyInfo: Sendable, Hashable {
    public let version: UInt64
    public let algorithmIdentifier: DERAlgorithmIdentifier
    public let algorithm: PublicKeyAlgorithm

    private let der: OwnedBytes
    private let privateKeyRange: ByteRange

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = PrivateKeyInfo.defaultParsingLimits
    ) throws(PrivateKeyInfoError) {
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
        } catch let error as DERError {
            throw .der(error)
        } catch {
            throw .invalidStructure
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard root.tag == sequenceTag else {
            throw .invalidStructure
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
            throw .der(error)
        } catch {
            throw .invalidStructure
        }

        let version: UInt64
        do {
            version = try DERPrimitiveCodec.decodePositiveInteger(from: versionElement)
        } catch let error as DERValueError {
            throw .value(error)
        } catch {
            throw .invalidStructure
        }
        guard version == 0 || version == 1 else {
            throw .invalidVersion(version)
        }

        let algorithmIdentifier: DERAlgorithmIdentifier
        do {
            algorithmIdentifier = try DERAlgorithmIdentifier.parse(
                from: algorithmElement,
                using: &budget
            )
        } catch let error as DERAlgorithmIdentifierError {
            throw .algorithm(error)
        } catch {
            throw .invalidStructure
        }

        let octetTag = DERTag(tagClass: .universal, isConstructed: false, number: 4)
        guard privateKeyElement.tag == octetTag else {
            throw .invalidStructure
        }
        let privateKeyRange: ByteRange
        do {
            privateKeyRange = try ByteRange(
                offset: privateKeyElement.encodedOffset + privateKeyElement.headerByteCount,
                count: privateKeyElement.contentBytes.count
            )
        } catch {
            throw .invalidRange(error)
        }

        var sawAttributes = false
        var sawPublicKey = false
        while !body.isAtEnd {
            let optionalElement: DERElementView
            do {
                optionalElement = try body.readElement(using: &budget)
            } catch let error as DERError {
                throw .der(error)
            } catch {
                throw .invalidStructure
            }
            switch (optionalElement.tag.tagClass, optionalElement.tag.isConstructed, optionalElement.tag.number) {
            case (.contextSpecific, true, 0):
                guard !sawAttributes else { throw .invalidStructure }
                sawAttributes = true
            case (.contextSpecific, false, 1):
                guard !sawPublicKey else { throw .invalidStructure }
                guard Self.validImplicitBitString(optionalElement.contentBytes) else {
                    throw .invalidPublicKeyField
                }
                sawPublicKey = true
            default:
                throw .invalidStructure
            }
        }
        guard version == (sawPublicKey ? 1 : 0) else {
            throw .invalidVersion(version)
        }

        self.version = version
        self.algorithmIdentifier = algorithmIdentifier
        self.algorithm = Self.mapAlgorithm(algorithmIdentifier)
        self.der = owned
        self.privateKeyRange = privateKeyRange
    }

    public var privateKeyByteCount: Int {
        privateKeyRange.count
    }

    public borrowing func withPrivateKeyBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: privateKeyRange)
        } catch {
            preconditionFailure("PrivateKeyInfo stores a validated private-key range")
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
