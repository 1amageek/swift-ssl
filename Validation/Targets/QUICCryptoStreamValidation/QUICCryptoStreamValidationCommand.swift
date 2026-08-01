import SwiftSSLCore
import SwiftSSLQUIC

@main
enum QUICCryptoStreamValidationCommand {
  enum Failure: Error {
    case incorrectBytes
    case incorrectOverlapFailure
  }

  static func main() throws {
    var stream = try QUICCryptoStreamReassembler(
      encryptionLevel: .handshake,
      maximumBufferedByteCount: 8
    )
    let tail: ContiguousArray<UInt8> = [3, 4]
    let head: ContiguousArray<UInt8> = [1, 2]
    try stream.receive(offset: 2, bytes: tail.span)
    try stream.receive(offset: 0, bytes: head.span)
    guard stream.withContiguousBytes({ copy($0) }) == [1, 2, 3, 4] else {
      throw Failure.incorrectBytes
    }
    try stream.discardContiguousBytes(count: 3)

    let wrapped: ContiguousArray<UInt8> = [5, 6, 7, 8, 9, 10, 11]
    try stream.receive(offset: 4, bytes: wrapped.span)
    guard stream.withContiguousBytes({ copy($0) }) == [4, 5, 6, 7, 8, 9, 10, 11] else {
      throw Failure.incorrectBytes
    }

    let conflict: ContiguousArray<UInt8> = [0]
    do {
      try stream.receive(offset: 7, bytes: conflict.span)
      throw Failure.incorrectOverlapFailure
    } catch let error as QUICCryptoStreamError {
      guard error == .conflictingOverlap(offset: 7) else {
        throw Failure.incorrectOverlapFailure
      }
    }

    print("swift-ssl QUIC CRYPTO stream validation: ok")
  }

  private static func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }
}
