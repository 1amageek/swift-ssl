import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

@main
enum HybridTargetValidationCommand {
  private enum Failure: Error {
    case entropy
    case clientShare
    case serverShare
    case sharedSecret
  }

  static func main() throws {
    try validateSystemEntropy()
    try validateHybridKeyExchange()
    print("swift-ssl hybrid target validation: ok")
  }

  private static func validateSystemEntropy() throws {
    var bytes = ContiguousArray<UInt8>(repeating: 0, count: 64)
    var destination = bytes.mutableSpan
    try SystemEntropySource().fill(&destination)
    var combined: UInt8 = 0
    var index = 0
    while index < bytes.count {
      combined |= bytes[index]
      index += 1
    }
    guard combined != 0 else { throw Failure.entropy }
  }

  private static func validateHybridKeyExchange() throws {
    var client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
      mlkemEntropy: FixedEntropy(bytes: sequential(count: 64, seed: 0x10)),
      x25519Entropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x30))
    )
    var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
    )
    let clientShare = client.withClientShare { OwnedBytes(copying: $0) }
    guard clientShare.count == TLS13NamedGroup.x25519MLKEM768.clientShareByteCount else {
      throw Failure.clientShare
    }
    let serverResult = try server.accept(
      clientShare: clientShare.span,
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x70))
    )
    guard serverResult.serverShare.count
      == TLS13NamedGroup.x25519MLKEM768.serverShareByteCount
    else {
      throw Failure.serverShare
    }
    let clientSecret = try client.complete(serverShare: serverResult.serverShare.span)
    let matches = clientSecret.withBorrowedBytes { clientBytes in
      serverResult.sharedSecret.withBorrowedBytes { serverBytes in
        guard clientBytes.count == 64, serverBytes.count == 64 else {
          return false
        }
        var difference: UInt8 = 0
        var index = 0
        while index < clientBytes.count {
          difference |= clientBytes[index] ^ serverBytes[index]
          index += 1
        }
        return difference == 0
      }
    }
    guard matches else { throw Failure.sharedSecret }
  }

  private static func sequential(
    count: Int,
    seed: UInt8
  ) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(count)
    var index = 0
    while index < count {
      result.append(seed &+ UInt8(truncatingIfNeeded: index))
      index += 1
    }
    return result
  }

  private struct FixedEntropy: EntropySource {
    let bytes: ContiguousArray<UInt8>

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      guard destination.count == bytes.count else {
        throw .partialFill(expected: destination.count, actual: bytes.count)
      }
      var index = 0
      while index < bytes.count {
        destination[index] = bytes[index]
        index += 1
      }
    }
  }
}
