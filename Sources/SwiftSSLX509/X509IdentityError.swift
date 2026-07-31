import SwiftSSLASN1

public enum X509IdentityError: Error, Sendable, Equatable {
    case invalidHostname
    case malformedSubjectAlternativeName
    case noMatchingSubjectAlternativeName
    case der(DERError)
}
