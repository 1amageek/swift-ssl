import SwiftSSLCore

public struct DERAlgorithmIdentifier: Sendable, Hashable {
    public let objectIdentifier: ContiguousArray<UInt64>
    public let parameters: DERAlgorithmParameters

    public static func parse(
        from element: DERElementView,
        using budget: inout ParsingBudget
    ) throws(DERAlgorithmIdentifierError) -> DERAlgorithmIdentifier {
        let expectedTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard element.tag == expectedTag else {
            throw .malformed
        }
        var cursor = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let oidElement: DERElementView
        do {
            oidElement = try cursor.readElement(using: &budget)
        } catch let error as DERError {
            throw .der(error)
        } catch {
            throw .malformed
        }
        let objectIdentifier: ContiguousArray<UInt64>
        do {
            try budget.requireOIDByteCount(oidElement.contentBytes.count)
            objectIdentifier = try DERPrimitiveCodec.decodeObjectIdentifier(from: oidElement)
        } catch let error as ResourceLimitError {
            throw .resourceLimit(error)
        } catch let error as DERValueError {
            throw .value(error)
        } catch {
            throw .malformed
        }

        var parameters: DERAlgorithmParameters = .absent
        if !cursor.isAtEnd {
            let parameterElement: DERElementView
            do {
                parameterElement = try cursor.readElement(using: &budget)
                try cursor.requireFullyConsumed()
            } catch let error as DERError {
                throw .der(error)
            } catch {
                throw .malformed
            }
            let nullTag = DERTag(tagClass: .universal, isConstructed: false, number: 5)
            let oidTag = DERTag(tagClass: .universal, isConstructed: false, number: 6)
            if parameterElement.tag == nullTag {
                guard parameterElement.contentBytes.count == 0 else {
                    throw .malformed
                }
                parameters = .null
            } else if parameterElement.tag == oidTag {
                do {
                    try budget.requireOIDByteCount(parameterElement.contentBytes.count)
                    parameters = .objectIdentifier(
                        try DERPrimitiveCodec.decodeObjectIdentifier(from: parameterElement)
                    )
                } catch let error as ResourceLimitError {
                    throw .resourceLimit(error)
                } catch let error as DERValueError {
                    throw .value(error)
                } catch {
                    throw .malformed
                }
            } else {
                parameters = .other
            }
        }

        do {
            try cursor.requireFullyConsumed()
        } catch let error as DERError {
            throw .der(error)
        } catch {
            throw .malformed
        }
        return DERAlgorithmIdentifier(
            objectIdentifier: objectIdentifier,
            parameters: parameters
        )
    }
}
