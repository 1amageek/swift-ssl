import SSLASN1
import SSLCore

public extension X509Certificate {
    /// Verifies a DNS server identity using subjectAltName only.
    ///
    /// Common Name is intentionally not consulted. A certificate wildcard is
    /// accepted only as the complete left-most label and therefore matches
    /// exactly one hostname label.
    func matchesDNSName(_ hostname: Span<UInt8>) throws(X509IdentityError) -> Bool {
        let canonicalHostname = try X509DNSName.canonicalHostname(hostname)
        guard let extensionValue = extensions.first(where: {
            $0.objectIdentifier == [2, 5, 29, 17]
        })?.value else {
            return false
        }

        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: extensionValue.count
            )
        } catch {
            throw .malformedSubjectAlternativeName
        }

        var cursor = DERCursor(extensionValue.span)
        let sequence: DERElementView
        do {
            sequence = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error as DERError {
            throw .der(error)
        } catch {
            throw .malformedSubjectAlternativeName
        }
        guard sequence.tag == DERTag(tagClass: .universal, isConstructed: true, number: 16) else {
            throw .malformedSubjectAlternativeName
        }

        var names = DERCursor(sequence.contentBytes)
        while !names.isAtEnd {
            let name: DERElementView
            do {
                name = try names.readElement(using: &budget)
            } catch let error as DERError {
                throw .der(error)
            } catch {
                throw .malformedSubjectAlternativeName
            }
            guard name.tag.tagClass == .contextSpecific, name.tag.number <= 8 else {
                throw .malformedSubjectAlternativeName
            }
            guard name.tag.number == 2 else { continue }
            guard !name.tag.isConstructed else { throw .malformedSubjectAlternativeName }
            let candidate: ContiguousArray<UInt8>
            do {
                candidate = try X509DNSName.canonicalCertificateName(name.contentBytes)
            } catch {
                throw .malformedSubjectAlternativeName
            }
            if X509DNSName.matches(candidate.span, hostname: canonicalHostname.span) {
                return true
            }
        }
        return false
    }

    /// Throws when the SAN-only identity check does not match.
    func verifyDNSName(_ hostname: Span<UInt8>) throws(X509IdentityError) {
        guard try matchesDNSName(hostname) else {
            throw .noMatchingSubjectAlternativeName
        }
    }
}

enum X509DNSName {
    static func canonicalHostname(_ input: Span<UInt8>) throws(X509IdentityError) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        var index = 0
        while index < input.count {
            let byte = input[index]
            guard byte < 0x80, byte != 0 else { throw .invalidHostname }
            result.append(asciiLower(byte))
            index += 1
        }
        if result.last == 0x2E { result.removeLast() }
        guard isValid(result.span, allowWildcard: false) else { throw .invalidHostname }
        return result
    }

    static func canonicalCertificateName(_ input: Span<UInt8>) throws(X509IdentityError) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        var index = 0
        while index < input.count {
            let byte = input[index]
            guard byte < 0x80, byte != 0 else { throw .invalidHostname }
            result.append(asciiLower(byte))
            index += 1
        }
        if result.last == 0x2E { result.removeLast() }
        guard isValid(result.span, allowWildcard: true) else { throw .invalidHostname }
        if result.first == 0x2A, !result.contains(0x2E) { throw .invalidHostname }
        return result
    }

    static func matches(_ candidate: Span<UInt8>, hostname: Span<UInt8>) -> Bool {
        let candidateLabels = labels(candidate)
        let hostnameLabels = labels(hostname)
        guard candidateLabels.count == hostnameLabels.count else { return false }
        var index = 0
        while index < candidateLabels.count {
            let candidateRange = candidateLabels[index]
            let hostnameRange = hostnameLabels[index]
            let candidateCount = candidateRange.count
            if candidateCount == 1, candidate[candidateRange.lowerBound] == 0x2A, index == 0 {
                index += 1
                continue
            }
            guard candidateCount == hostnameRange.count else { return false }
            var byteIndex = 0
            while byteIndex < candidateCount {
                guard candidate[candidateRange.lowerBound + byteIndex] == hostname[hostnameRange.lowerBound + byteIndex] else {
                    return false
                }
                byteIndex += 1
            }
            index += 1
        }
        return true
    }

    private static func isValid(_ name: Span<UInt8>, allowWildcard: Bool) -> Bool {
        guard !name.isEmpty, name.count <= 253 else { return false }
        var labelStart = 0
        var index = 0
        while index <= name.count {
            let atEnd = index == name.count
            if atEnd || name[index] == 0x2E {
                let labelCount = index - labelStart
                guard labelCount > 0, labelCount <= 63 else { return false }
                if allowWildcard, labelStart == 0, labelCount == 1, name[labelStart] == 0x2A {
                    // Only the complete left-most label may be a wildcard.
                } else {
                    var labelIndex = labelStart
                    while labelIndex < index {
                        let byte = name[labelIndex]
                        let isAlpha = (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39)
                        guard isAlpha || byte == 0x2D else { return false }
                        labelIndex += 1
                    }
                    guard name[labelStart] != 0x2D, name[index - 1] != 0x2D else { return false }
                }
                labelStart = index + 1
            }
            index += 1
        }
        return true
    }

    private static func labels(_ bytes: Span<UInt8>) -> [Range<Int>] {
        var result: [Range<Int>] = []
        var start = 0
        var index = 0
        while index <= bytes.count {
            if index == bytes.count || bytes[index] == 0x2E {
                result.append(start..<index)
                start = index + 1
            }
            index += 1
        }
        return result
    }

    @inline(__always)
    private static func asciiLower(_ byte: UInt8) -> UInt8 {
        byte >= 0x41 && byte <= 0x5A ? byte + 0x20 : byte
    }
}
