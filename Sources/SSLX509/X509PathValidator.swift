import SSLASN1
import SSLCore

/// Bounded RFC 5280 path validation over caller-owned certificate records.
///
/// The validator owns no network, filesystem, or platform trust-store state.
/// Callers supply immutable trust anchors and an ordered or unordered set of
/// intermediates; path construction is a bounded search over those records.
public struct X509PathValidator: Sendable {
    public static let maximumPathLength = 8

    private let trustAnchors: ContiguousArray<X509Certificate>
    private let policy: any X509PathPolicyEvaluating

    public init(
        trustAnchors: ContiguousArray<X509Certificate>,
        policy: any X509PathPolicyEvaluating = RFC5280ServerPathPolicy()
    ) throws(X509PathError) {
        guard !trustAnchors.isEmpty else {
            throw .emptyTrustStore
        }
        self.trustAnchors = trustAnchors
        self.policy = policy
    }

    /// Validates a leaf against the configured anchors at one instant.
    ///
    /// `intermediates` may be unordered. A hostname, when supplied, is
    /// checked against the leaf's SAN-only identity policy after the chain is
    /// cryptographically and temporally valid.
    @discardableResult
    public func validate(
        leaf: X509Certificate,
        intermediates: ContiguousArray<X509Certificate> = [],
        at instant: VerificationInstant,
        hostname: Span<UInt8>? = nil
    ) throws(X509PathError) -> X509ValidatedPath {
        guard Self.maximumPathLength > 0 else {
            throw .invalidPathLength
        }
        guard leaf.validity.contains(instant) else {
            throw .certificateNotValid
        }

        var pending: [ContiguousArray<X509Certificate>] = [ContiguousArray([leaf])]
        var lastFailure: X509PathError = .issuerNotFound
        var exploredPathCount = 0

        while !pending.isEmpty {
            let path = pending.removeFirst()
            exploredPathCount += 1
            guard exploredPathCount <= Self.maximumPathLength * 16 else {
                throw .pathTooLong(limit: Self.maximumPathLength)
            }
            let current = path[path.count - 1]

            if Self.containsExact(current, in: trustAnchors) {
                try policy.evaluate(path: path, hostname: hostname)
                return X509ValidatedPath(certificates: path)
            }

            guard path.count < Self.maximumPathLength else {
                lastFailure = .pathTooLong(limit: Self.maximumPathLength)
                continue
            }

            let candidates = Self.candidates(
                intermediates: intermediates,
                trustAnchors: trustAnchors
            )
            var foundIssuer = false
            for candidate in candidates {
                guard candidate.subjectName == current.issuerName else {
                    continue
                }
                foundIssuer = true
                guard !Self.containsExact(candidate, in: path) else {
                    lastFailure = .loopDetected
                    continue
                }
                guard candidate.validity.contains(instant) else {
                    lastFailure = .certificateNotValid
                    continue
                }
                do {
                    try Self.validateIssuerConstraints(
                        candidate,
                        caBelow: path.count - 1
                    )
                    try current.verifySignature(using: candidate.subjectPublicKeyInfo)
                } catch let error as X509PathError {
                    lastFailure = error
                    continue
                } catch let error as X509CertificateError {
                    lastFailure = .signature(error)
                    continue
                } catch {
                    lastFailure = .signature(.signatureVerificationFailed)
                    continue
                }

                var next = path
                next.append(candidate)
                if Self.containsExact(candidate, in: trustAnchors) {
                    try policy.evaluate(path: next, hostname: hostname)
                    return X509ValidatedPath(certificates: next)
                }
                pending.append(next)
            }
            if !foundIssuer {
                lastFailure = .issuerNotFound
            }
        }

        throw lastFailure
    }

    private static func candidates(
        intermediates: ContiguousArray<X509Certificate>,
        trustAnchors: ContiguousArray<X509Certificate>
    ) -> ContiguousArray<X509Certificate> {
        var result = ContiguousArray<X509Certificate>()
        result.reserveCapacity(intermediates.count + trustAnchors.count)
        for certificate in intermediates where !containsExact(certificate, in: result) {
            result.append(certificate)
        }
        for certificate in trustAnchors where !containsExact(certificate, in: result) {
            result.append(certificate)
        }
        return result
    }

    private static func containsExact(
        _ certificate: X509Certificate,
        in collection: ContiguousArray<X509Certificate>
    ) -> Bool {
        for candidate in collection where candidate == certificate {
            return true
        }
        return false
    }

    private static func validateIssuerConstraints(
        _ issuer: X509Certificate,
        caBelow: Int
    ) throws(X509PathError) {
        guard caBelow >= 0 else { throw .invalidPathLength }
        guard let basicConstraints = issuer.extensions.first(where: {
            $0.objectIdentifier == [2, 5, 29, 19]
        }) else {
            throw .issuerNotCA
        }

        let limits = X509Certificate.defaultParsingLimits
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: basicConstraints.value.count)
        } catch {
            throw .invalidBasicConstraints
        }
        var cursor = DERCursor(basicConstraints.value.span)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .invalidBasicConstraints
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard root.tag == sequenceTag else { throw .invalidBasicConstraints }

        var body = DERCursor(root.contentBytes)
        var isCA = false
        var pathLength: UInt64?
        if !body.isAtEnd {
            let first: DERElementView
            do { first = try body.readElement(using: &budget) }
            catch { throw .invalidBasicConstraints }
            let booleanTag = DERTag(tagClass: .universal, isConstructed: false, number: 1)
            if first.tag == booleanTag {
                do { isCA = try DERPrimitiveCodec.decodeBoolean(from: first) }
                catch { throw .invalidBasicConstraints }
                if !body.isAtEnd {
                    let pathElement: DERElementView
                    do { pathElement = try body.readElement(using: &budget) }
                    catch { throw .invalidBasicConstraints }
                    do { pathLength = try DERPrimitiveCodec.decodePositiveInteger(from: pathElement) }
                    catch { throw .invalidBasicConstraints }
                }
            } else {
                do { pathLength = try DERPrimitiveCodec.decodePositiveInteger(from: first) }
                catch { throw .invalidBasicConstraints }
            }
        }
        do { try body.requireFullyConsumed() }
        catch { throw .invalidBasicConstraints }
        guard isCA else { throw .issuerNotCA }
        if let pathLength, UInt64(caBelow) > pathLength {
            throw .pathTooLong(limit: Int(pathLength))
        }

        if let keyUsage = issuer.extensions.first(where: {
            $0.objectIdentifier == [2, 5, 29, 15]
        }) {
            var usageBudget: ParsingBudget
            do {
                usageBudget = try ParsingBudget(limits: limits, inputByteCount: keyUsage.value.count)
            } catch {
                throw .issuerKeyUsageViolation
            }
            var usageCursor = DERCursor(keyUsage.value.span)
            let usageElement: DERElementView
            do {
                usageElement = try usageCursor.readElement(using: &usageBudget)
                try usageCursor.requireFullyConsumed()
            } catch {
                throw .issuerKeyUsageViolation
            }
            let usage: DERBitString
            do { usage = try DERPrimitiveCodec.decodeBitString(from: usageElement) }
            catch { throw .issuerKeyUsageViolation }
            guard !usage.bytes.isEmpty, usage.bytes.span[0] & 0x04 != 0 else {
                throw .issuerKeyUsageViolation
            }
        }
    }
}
