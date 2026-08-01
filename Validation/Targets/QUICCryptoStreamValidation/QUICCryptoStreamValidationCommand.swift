import SwiftSSLCore
import SwiftSSLQUIC
import SwiftSSLTLS

@main
enum QUICCryptoStreamValidationCommand {
  enum Failure: Error {
    case incorrectBytes
    case incorrectOverlapFailure
  }

  static func main() throws {
    var stream = try QUICTLSHandshakeStream.make(
      encryptionLevel: .handshake,
      maximumBufferedByteCount: 8,
      maximumMessageByteCount: 8
    )
    let first: ContiguousArray<UInt8> = [1, 0, 0, 1, 0xAA]
    try stream.receive(offset: 0, bytes: first.span)
    guard try stream.withNextMessage({ copy($0) }) == first else {
      throw Failure.incorrectBytes
    }
    try stream.discardNextMessage()

    let tail: ContiguousArray<UInt8> = [0xBB, 0xCC]
    let head: ContiguousArray<UInt8> = [2, 0, 0, 2]
    try stream.receive(offset: 9, bytes: tail.span)
    try stream.receive(offset: 5, bytes: head.span)
    guard try stream.withNextMessage({ copy($0) }) == [2, 0, 0, 2, 0xBB, 0xCC] else {
      throw Failure.incorrectBytes
    }

    let conflict: ContiguousArray<UInt8> = [1]
    do {
      try stream.receive(offset: 7, bytes: conflict.span)
      throw Failure.incorrectOverlapFailure
    } catch let error as QUICTLSHandshakeStreamError {
      guard error == .reassembly(.conflictingOverlap(offset: 7)) else {
        throw Failure.incorrectOverlapFailure
      }
    }

    print("swift-ssl QUIC TLS handshake stream validation: ok")
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
