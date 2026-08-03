import SwiftSSLCore
import SwiftSSLCrypto

public protocol DTLS13RecordProtecting: Sendable, ~Copyable {
  var cipherSuite: TLSCipherSuite { get }
  var epoch: UInt64 { get }
  var currentSequenceNumber: UInt64 { get }

  mutating func seal(
    content: Span<UInt8>,
    contentType: DTLS13RecordContentType,
    paddingByteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(DTLS13RecordError) -> DTLS13RecordNumber

  mutating func open(
    record: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(DTLS13RecordError) -> DTLS13RecordContentType
}
