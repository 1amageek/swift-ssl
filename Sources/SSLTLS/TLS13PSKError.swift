import SSLCore

public enum TLS13PSKError: Error, Sendable, Equatable {
    case emptyIdentity
    case invalidIdentityLength(Int)
    case invalidBinderLength(Int)
    case identityBinderCountMismatch
    case malformedExtension
    case duplicateIdentity
    case encodedLengthExceeded(Int)
    case derivationFailed
}
