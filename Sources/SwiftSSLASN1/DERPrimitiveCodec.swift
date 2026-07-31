import SwiftSSLCore

public enum DERPrimitiveCodec {
    public static func decodeBoolean(
        from element: DERElementView
    ) throws(DERValueError) -> Bool {
        try requireTag(element, number: 1, constructed: false)
        guard element.contentBytes.count == 1 else {
            throw .invalidBoolean
        }
        switch element.contentBytes[0] {
        case 0:
            return false
        case 0xFF:
            return true
        default:
            throw .invalidBoolean
        }
    }

    public static func decodePositiveInteger(
        from element: DERElementView
    ) throws(DERValueError) -> UInt64 {
        try requireTag(element, number: 2, constructed: false)
        let bytes = element.contentBytes
        guard !bytes.isEmpty else {
            throw .emptyInteger
        }
        if bytes.count > 1 {
            let first = bytes[0]
            let second = bytes[1]
            guard !(first == 0 && (second & 0x80) == 0) else {
                throw .nonCanonicalInteger
            }
        }
        guard (bytes[0] & 0x80) == 0 else {
            throw .negativeInteger
        }
        var value: UInt64 = 0
        var index = 0
        while index < bytes.count {
            let (shifted, overflow) = value.multipliedReportingOverflow(by: 256)
            let (updated, addOverflow) = shifted.addingReportingOverflow(UInt64(bytes[index]))
            guard !overflow, !addOverflow else {
                throw .integerOverflow
            }
            value = updated
            index += 1
        }
        return value
    }

    public static func decodeOctetString(
        from element: DERElementView
    ) throws(DERValueError) -> OwnedBytes {
        try requireTag(element, number: 4, constructed: false)
        return OwnedBytes(copying: element.contentBytes)
    }

    public static func decodeBitString(
        from element: DERElementView
    ) throws(DERValueError) -> DERBitString {
        try requireTag(element, number: 3, constructed: false)
        let content = element.contentBytes
        guard !content.isEmpty, content[0] <= 7 else {
            throw .invalidBitString
        }
        let payload = content.extracting(1..<content.count)
        if payload.isEmpty, content[0] != 0 {
            throw .invalidBitString
        }
        if !payload.isEmpty, content[0] != 0 {
            let last = payload[payload.count - 1]
            let mask = UInt8((1 << content[0]) - 1)
            guard (last & mask) == 0 else {
                throw .invalidBitString
            }
        }
        return DERBitString(
            unusedBitCount: content[0],
            bytes: OwnedBytes(copying: payload)
        )
    }

    public static func decodeObjectIdentifier(
        from element: DERElementView
    ) throws(DERValueError) -> ContiguousArray<UInt64> {
        try requireTag(element, number: 6, constructed: false)
        let content = element.contentBytes
        guard !content.isEmpty else {
            throw .invalidObjectIdentifier
        }
        var components = ContiguousArray<UInt64>()
        var value: UInt64 = 0
        var hasTerminatedComponent = false
        var componentByteCount = 0
        var index = 0
        while index < content.count {
            let byte = content[index]
            if componentByteCount == 0, byte & 0x80 != 0, byte & 0x7F == 0 {
                throw .invalidObjectIdentifier
            }
            let (shifted, overflow) = value.multipliedReportingOverflow(by: 128)
            let (updated, addOverflow) = shifted.addingReportingOverflow(UInt64(byte & 0x7F))
            guard !overflow, !addOverflow else {
                throw .objectIdentifierOverflow
            }
            value = updated
            componentByteCount += 1
            if byte & 0x80 == 0 {
                if components.isEmpty {
                    if value < 40 {
                        components.append(0)
                        components.append(value)
                    } else if value < 80 {
                        components.append(1)
                        components.append(value - 40)
                    } else {
                        components.append(2)
                        components.append(value - 80)
                    }
                } else {
                    components.append(value)
                }
                value = 0
                componentByteCount = 0
                hasTerminatedComponent = true
            } else {
                hasTerminatedComponent = false
            }
            index += 1
        }
        guard hasTerminatedComponent else {
            throw .invalidObjectIdentifier
        }
        return components
    }

    private static func requireTag(
        _ element: DERElementView,
        number: UInt,
        constructed: Bool
    ) throws(DERValueError) {
        let expected = DERTag(
            tagClass: .universal,
            isConstructed: constructed,
            number: number
        )
        guard element.tag == expected else {
            throw .unexpectedTag(expected: expected, actual: element.tag)
        }
    }
}
