import SwiftSSLCore

package protocol TLSBatchAction: Sendable {
    var referencedByteRange: ByteRange? { get }
}
