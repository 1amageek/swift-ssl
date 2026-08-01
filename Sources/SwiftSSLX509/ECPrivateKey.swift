import SwiftSSLCore
import SwiftSSLASN1

/// RFC 5915 ECPrivateKey with scoped access to the private scalar.
///
/// The parser owns a dedicated wiped allocation for the scalar and a normal
/// immutable owner for the optional public point. It validates the DER
/// structure and curve-sized encodings, while the curve-specific crypto key
/// types perform scalar range and point-equation validation before use.
public struct ECPrivateKey: ~Copyable, Sendable {
    public let version: UInt64
    public let curve: NamedCurve
    public let parametersObjectIdentifier: ContiguousArray<UInt64>?
    public let publicKey: OwnedBytes?

    private let privateKey: SecretBytes

    public init(
        der encodedDER: Span<UInt8>,
        expectedCurve: NamedCurve? = nil,
        limits: ParsingLimits = ECPrivateKey.defaultParsingLimits
    ) throws(ECPrivateKeyError) {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: encodedDER.count)
        } catch {
            throw .resourceLimit(error)
        }

        var cursor = DERCursor(encodedDER)
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
        guard root.tag == sequenceTag else { throw .invalidStructure }

        var body = DERCursor(root.contentBytes)
        let versionElement: DERElementView
        let privateKeyElement: DERElementView
        do {
            versionElement = try body.readElement(using: &budget)
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
        guard version == 1 else { throw .invalidVersion(version) }

        let octetTag = DERTag(tagClass: .universal, isConstructed: false, number: 4)
        guard privateKeyElement.tag == octetTag else { throw .invalidStructure }
        let scalarBytes = privateKeyElement.contentBytes

        var parameterOID: ContiguousArray<UInt64>?
        var publicKey: OwnedBytes?
        var sawParameters = false
        var sawPublicKey = false
        while !body.isAtEnd {
            let element: DERElementView
            do {
                element = try body.readElement(using: &budget)
            } catch let error as DERError {
                throw .der(error)
            } catch {
                throw .invalidStructure
            }

            switch (element.tag.tagClass, element.tag.isConstructed, element.tag.number) {
            case (.contextSpecific, true, 0):
                guard !sawParameters, !sawPublicKey else { throw .invalidStructure }
                sawParameters = true
                var parameterCursor = DERCursor(element.contentBytes)
                let oidElement: DERElementView
                do {
                    oidElement = try parameterCursor.readElement(using: &budget)
                    try parameterCursor.requireFullyConsumed()
                } catch let error as DERError {
                    throw .der(error)
                } catch {
                    throw .invalidStructure
                }
                do {
                    try budget.requireOIDByteCount(oidElement.contentBytes.count)
                    parameterOID = try DERPrimitiveCodec.decodeObjectIdentifier(from: oidElement)
                } catch let error as ResourceLimitError {
                    throw .resourceLimit(error)
                } catch let error as DERValueError {
                    throw .value(error)
                } catch {
                    throw .invalidStructure
                }

            case (.contextSpecific, false, 1):
                guard !sawPublicKey else { throw .invalidStructure }
                guard Self.validImplicitBitString(element.contentBytes) else {
                    throw .invalidPublicKeyField
                }
                sawPublicKey = true
                publicKey = OwnedBytes(copying: element.contentBytes.extracting(droppingFirst: 1))

            default:
                throw .invalidStructure
            }
        }

        let curve = Self.mapCurve(parameterOID)
        if let expectedCurve {
            guard curve == expectedCurve else { throw .invalidParameters }
        }
        if let expectedByteCount = Self.byteCount(for: curve) {
            guard scalarBytes.count == expectedByteCount else {
                throw .invalidPrivateKeyLength(expected: expectedByteCount, actual: scalarBytes.count)
            }
            if let publicKey {
                guard publicKey.count == (1 + (expectedByteCount * 2)), publicKey[0] == 0x04 else {
                    throw .invalidPublicKeyField
                }
            }
        }

        let privateKey: SecretBytes
        do {
            privateKey = try SecretBytes(copying: scalarBytes)
        } catch let error {
            throw .memoryFailure(error)
        }

        self.version = version
        self.curve = curve
        self.parametersObjectIdentifier = parameterOID
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public var privateKeyByteCount: Int { privateKey.count }

    public borrowing func withPrivateKeyBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try privateKey.withBorrowedBytes(body)
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
            preconditionFailure("ECPrivateKey limits are compile-time constants")
        }
    }()

    private static func validImplicitBitString(_ content: Span<UInt8>) -> Bool {
        guard !content.isEmpty, content[0] <= 7 else { return false }
        let payload = content.extracting(droppingFirst: 1)
        if payload.isEmpty { return content[0] == 0 }
        guard content[0] != 0 else { return true }
        let mask = UInt8((1 << content[0]) - 1)
        return (payload[payload.count - 1] & mask) == 0
    }

    private static func mapCurve(_ oid: ContiguousArray<UInt64>?) -> NamedCurve {
        switch oid.map(Array.init) {
        case [1, 2, 840, 10045, 3, 1, 7]: return .prime256v1
        case [1, 3, 132, 0, 34]: return .secp384r1
        case [1, 3, 132, 0, 35]: return .secp521r1
        default:
            return .unknown(objectIdentifier: oid ?? [])
        }
    }

    private static func byteCount(for curve: NamedCurve) -> Int? {
        switch curve {
        case .prime256v1: return 32
        case .secp384r1: return 48
        case .secp521r1: return 66
        case .unknown: return nil
        }
    }
}
