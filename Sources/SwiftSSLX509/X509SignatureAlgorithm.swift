import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto

/// A parsed signature algorithm that retains the policy-relevant parameters
/// required to verify arbitrary X.509 signed objects such as certificates,
/// CRLs, and OCSP responses.
public struct X509SignatureAlgorithm: Sendable, Hashable {
    public let identifier: DERAlgorithmIdentifier

    let rsaPSSHash: RSAPSSHash?
    let rsaPSSSaltLength: Int?

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = X509Certificate.defaultParsingLimits
    ) throws(X509SignatureVerificationError) {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: encodedDER.count
            )
        } catch let error {
            throw .resourceLimit(error)
        }
        var cursor = DERCursor(encodedDER)
        let element: DERElementView
        do {
            element = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        try self.init(element: element, budget: &budget)
    }

    internal init(
        element: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509SignatureVerificationError) {
        do {
            identifier = try DERAlgorithmIdentifier.parse(
                from: element,
                using: &budget
            )
        } catch let error {
            throw .algorithm(error)
        }
        if identifier.objectIdentifier == Self.rsaPSSOID {
            let parameters = try Self.parseRSAPSSParameters(
                element,
                budget: &budget
            )
            rsaPSSHash = parameters.hash
            rsaPSSSaltLength = parameters.saltLength
        } else {
            rsaPSSHash = nil
            rsaPSSSaltLength = nil
        }
    }

    private static func parseRSAPSSParameters(
        _ algorithmElement: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509SignatureVerificationError) -> (
        hash: RSAPSSHash,
        saltLength: Int
    ) {
        guard algorithmElement.tag == sequenceTag else {
            throw .unsupportedAlgorithm
        }
        var algorithmBody = DERCursor(algorithmElement.contentBytes)
        do {
            _ = try algorithmBody.readElement(using: &budget)
        } catch {
            throw .unsupportedAlgorithm
        }
        let parameters: DERElementView
        do {
            parameters = try algorithmBody.readElement(using: &budget)
            try algorithmBody.requireFullyConsumed()
        } catch {
            throw .unsupportedAlgorithm
        }
        guard parameters.tag == sequenceTag else {
            throw .unsupportedAlgorithm
        }

        var hash: RSAPSSHash?
        var mgfHash: RSAPSSHash?
        var saltLength: Int?
        var trailerField: UInt64?
        var parameterBody = DERCursor(parameters.contentBytes)
        while !parameterBody.isAtEnd {
            let field: DERElementView
            do {
                field = try parameterBody.readElement(using: &budget)
            } catch {
                throw .unsupportedAlgorithm
            }
            guard field.tag.tagClass == .contextSpecific,
                  field.tag.isConstructed,
                  field.tag.number <= 3 else {
                throw .unsupportedAlgorithm
            }
            var innerCursor = DERCursor(field.contentBytes)
            let inner: DERElementView
            do {
                inner = try innerCursor.readElement(using: &budget)
                try innerCursor.requireFullyConsumed()
            } catch {
                throw .unsupportedAlgorithm
            }
            switch field.tag.number {
            case 0:
                guard hash == nil else { throw .unsupportedAlgorithm }
                hash = try parseRSASHA2Algorithm(inner, budget: &budget)
            case 1:
                guard mgfHash == nil else { throw .unsupportedAlgorithm }
                mgfHash = try parseRSAMGF1Algorithm(inner, budget: &budget)
            case 2:
                guard saltLength == nil else { throw .unsupportedAlgorithm }
                let value: UInt64
                do {
                    value = try DERPrimitiveCodec.decodePositiveInteger(
                        from: inner
                    )
                } catch {
                    throw .unsupportedAlgorithm
                }
                guard value <= UInt64(Int.max) else {
                    throw .unsupportedAlgorithm
                }
                saltLength = Int(value)
            case 3:
                guard trailerField == nil else {
                    throw .unsupportedAlgorithm
                }
                do {
                    trailerField = try DERPrimitiveCodec
                        .decodePositiveInteger(from: inner)
                } catch {
                    throw .unsupportedAlgorithm
                }
            default:
                throw .unsupportedAlgorithm
            }
        }
        guard let hash,
              let mgfHash,
              hash == mgfHash,
              let saltLength,
              saltLength == hash.digestByteCount,
              trailerField == nil || trailerField == 1 else {
            throw .unsupportedAlgorithm
        }
        return (hash, saltLength)
    }

    private static func parseRSASHA2Algorithm(
        _ algorithmElement: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509SignatureVerificationError) -> RSAPSSHash {
        guard algorithmElement.tag == sequenceTag else {
            throw .unsupportedAlgorithm
        }
        var body = DERCursor(algorithmElement.contentBytes)
        let oidElement: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
        } catch {
            throw .unsupportedAlgorithm
        }
        let oid: ContiguousArray<UInt64>
        do {
            oid = try DERPrimitiveCodec.decodeObjectIdentifier(from: oidElement)
        } catch {
            throw .unsupportedAlgorithm
        }
        if !body.isAtEnd {
            let parameters: DERElementView
            do {
                parameters = try body.readElement(using: &budget)
                try body.requireFullyConsumed()
            } catch {
                throw .unsupportedAlgorithm
            }
            guard parameters.tag == nullTag,
                  parameters.contentBytes.isEmpty else {
                throw .unsupportedAlgorithm
            }
        }
        switch oid {
        case sha256OID: return .sha256
        case sha384OID: return .sha384
        case sha512OID: return .sha512
        default: throw .unsupportedAlgorithm
        }
    }

    private static func parseRSAMGF1Algorithm(
        _ algorithmElement: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509SignatureVerificationError) -> RSAPSSHash {
        guard algorithmElement.tag == sequenceTag else {
            throw .unsupportedAlgorithm
        }
        var body = DERCursor(algorithmElement.contentBytes)
        let oidElement: DERElementView
        do {
            oidElement = try body.readElement(using: &budget)
        } catch {
            throw .unsupportedAlgorithm
        }
        let oid: ContiguousArray<UInt64>
        do {
            oid = try DERPrimitiveCodec.decodeObjectIdentifier(from: oidElement)
        } catch {
            throw .unsupportedAlgorithm
        }
        guard oid == mgf1OID, !body.isAtEnd else {
            throw .unsupportedAlgorithm
        }
        let parameters: DERElementView
        do {
            parameters = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch {
            throw .unsupportedAlgorithm
        }
        return try parseRSASHA2Algorithm(parameters, budget: &budget)
    }

    private static let rsaPSSOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 10,
    ]
    private static let mgf1OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 8,
    ]
    private static let sha256OID: ContiguousArray<UInt64> = [
        2, 16, 840, 1, 101, 3, 4, 2, 1,
    ]
    private static let sha384OID: ContiguousArray<UInt64> = [
        2, 16, 840, 1, 101, 3, 4, 2, 2,
    ]
    private static let sha512OID: ContiguousArray<UInt64> = [
        2, 16, 840, 1, 101, 3, 4, 2, 3,
    ]
    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let nullTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 5
    )
}
