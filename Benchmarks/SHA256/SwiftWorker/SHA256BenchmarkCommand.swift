import SwiftSSLCore
import SwiftSSLCrypto

@main
enum SHA256BenchmarkCommand {
  private enum ArgumentError: Error {
    case invalidArguments
  }

  static func main() throws {
    let arguments = CommandLine.arguments
    if arguments.count == 4, arguments[1] == "--validate" {
      guard
        let byteCount = Int(arguments[2]),
        let iterations = Int(arguments[3]),
        byteCount > 0,
        iterations > 0
      else {
        throw ArgumentError.invalidArguments
      }
      try validate(byteCount: byteCount, iterations: iterations)
      return
    }

    guard arguments.count == 4,
      let byteCount = Int(arguments[1]),
      let iterations = Int(arguments[2]),
      let warmupIterations = Int(arguments[3]),
      byteCount > 0,
      iterations > 0,
      warmupIterations >= 0
    else {
      throw ArgumentError.invalidArguments
    }

    var warmupInput = makeInput(byteCount: byteCount)
    var warmupOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)
    _ = try run(
      input: &warmupInput,
      output: &warmupOutput,
      iterations: warmupIterations
    )

    var input = makeInput(byteCount: byteCount)
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let clock = ContinuousClock()
    let start = clock.now
    let checksum = try run(
      input: &input,
      output: &output,
      iterations: iterations
    )
    let elapsed = start.duration(to: clock.now).components
    let nanoseconds =
      elapsed.seconds * 1_000_000_000
      + elapsed.attoseconds / 1_000_000_000

    print("RESULT,\(nanoseconds),\(checksum),\(hexString(output.span))")
  }

  private static func validate(
    byteCount: Int,
    iterations: Int
  ) throws(CryptoInputError) {
    var input = makeInput(byteCount: byteCount)
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var inputSpan = input.mutableSpan
    var outputSpan = output.mutableSpan
    var iteration = 0
    while iteration < iterations {
      inputSpan[0] = UInt8(truncatingIfNeeded: iteration)
      try SHA256.hash(inputSpan.span, into: &outputSpan)
      print("DIGEST,\(iteration),\(hexString(outputSpan.span))")
      iteration += 1
    }
  }

  private static func makeInput(byteCount: Int) -> ContiguousArray<UInt8> {
    var input = ContiguousArray<UInt8>()
    input.reserveCapacity(byteCount)
    var index = 0
    while index < byteCount {
      input.append(UInt8(truncatingIfNeeded: index &* 31 &+ 17))
      index += 1
    }
    return input
  }

  @inline(never)
  private static func run(
    input: inout ContiguousArray<UInt8>,
    output: inout ContiguousArray<UInt8>,
    iterations: Int
  ) throws(CryptoInputError) -> UInt64 {
    var inputSpan = input.mutableSpan
    var outputSpan = output.mutableSpan
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      inputSpan[0] = UInt8(truncatingIfNeeded: iteration)
      try SHA256.hash(inputSpan.span, into: &outputSpan)
      checksum &+= UInt64(outputSpan[iteration & 31])
      iteration += 1
    }
    return checksum
  }

  private static func hexString(_ bytes: Span<UInt8>) -> String {
    let digits = ContiguousArray("0123456789abcdef".utf8)
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(bytes.count * 2)
    var index = 0
    while index < bytes.count {
      let byte = bytes[index]
      encoded.append(digits[Int(byte >> 4)])
      encoded.append(digits[Int(byte & 0x0F)])
      index += 1
    }
    return String(decoding: encoded, as: UTF8.self)
  }
}
