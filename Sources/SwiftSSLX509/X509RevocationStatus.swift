import SwiftSSLCore

public enum X509RevocationStatus: Sendable, Hashable {
    case good
    case revoked(at: VerificationInstant)
}
