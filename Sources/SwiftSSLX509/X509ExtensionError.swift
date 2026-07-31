import SwiftSSLASN1
import SwiftSSLCore

public enum X509ExtensionError: Error, Sendable, Equatable {
    case invalidStructure
    case der(DERError)
    case value(DERValueError)
    case duplicateObjectIdentifier
    case resourceLimit(ResourceLimitError)
}
