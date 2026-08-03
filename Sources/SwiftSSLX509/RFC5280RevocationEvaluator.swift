import SwiftSSLCore

/// Applies explicit hard-fail or soft-fail policy to pre-acquired CRL/OCSP
/// evidence. A cryptographically valid revoked result is never softened.
public struct RFC5280RevocationEvaluator:
    X509RevocationEvidenceValidating,
    Sendable
{
    public let policy: X509RevocationPolicy

    public init(policy: X509RevocationPolicy) {
        self.policy = policy
    }

    public func evaluate(
        path: borrowing ContiguousArray<X509Certificate>,
        evidence: borrowing ContiguousArray<X509RevocationEvidence>,
        trustedOCSPResponders: borrowing ContiguousArray<X509Certificate> = [],
        at instant: VerificationInstant
    ) throws(X509RevocationError) {
        guard !path.isEmpty else { throw .invalidPathLength }
        guard policy.mode != .disabled else { return }
        guard path.count > 1 else { return }
        let certificateCount = policy.checksIntermediates
            ? path.count - 1
            : 1
        var certificateIndex = 0
        while certificateIndex < certificateCount {
            let certificate = path[certificateIndex]
            let issuer = path[certificateIndex + 1]
            var acceptedEvidence = false
            var lastFailure: X509RevocationError?
            var evidenceIndex = 0
            while evidenceIndex < evidence.count {
                switch evidence[evidenceIndex] {
                case .ocsp(let response):
                    do {
                        let status = try response.evaluate(
                            certificate: certificate,
                            issuer: issuer,
                            at: instant,
                            trustedResponders: trustedOCSPResponders,
                            policy: policy.ocspPolicy
                        )
                        acceptedEvidence = true
                        if case .revoked(let revocationTime) = status {
                            throw X509RevocationError.revoked(
                                certificateIndex: certificateIndex,
                                at: revocationTime
                            )
                        }
                    } catch let error as X509RevocationError {
                        throw error
                    } catch let error as OCSPResponseError {
                        if error != .matchingCertificateStatusNotFound {
                            lastFailure = .ocsp(
                                certificateIndex: certificateIndex,
                                error
                            )
                        }
                    } catch {
                        lastFailure = .ocsp(
                            certificateIndex: certificateIndex,
                            .invalidStructure
                        )
                    }
                case .crl(let list):
                    do {
                        let status = try list.evaluate(
                            certificate: certificate,
                            issuer: issuer,
                            at: instant,
                            policy: policy.crlPolicy
                        )
                        acceptedEvidence = true
                        if case .revoked(let revocationTime) = status {
                            throw X509RevocationError.revoked(
                                certificateIndex: certificateIndex,
                                at: revocationTime
                            )
                        }
                    } catch let error as X509RevocationError {
                        throw error
                    } catch let error as X509CertificateRevocationListError {
                        if error != .issuerMismatch {
                            lastFailure = .crl(
                                certificateIndex: certificateIndex,
                                error
                            )
                        }
                    } catch {
                        lastFailure = .crl(
                            certificateIndex: certificateIndex,
                            .invalidStructure
                        )
                    }
                }
                evidenceIndex += 1
            }
            if !acceptedEvidence, policy.mode == .hardFail {
                if let lastFailure { throw lastFailure }
                throw .evidenceRequired(certificateIndex: certificateIndex)
            }
            certificateIndex += 1
        }
    }
}
