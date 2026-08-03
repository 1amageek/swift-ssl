public enum X509DelegationUsageError: Error, Sendable, Equatable {
    case missingDelegationUsage
    case duplicateDelegationUsage
    case criticalDelegationUsage
    case malformedDelegationUsage
    case missingKeyUsage
    case malformedKeyUsage
    case digitalSignatureRequired
}
