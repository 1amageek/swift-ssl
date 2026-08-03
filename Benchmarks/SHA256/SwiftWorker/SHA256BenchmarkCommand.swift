import SwiftSSLCore
import SwiftSSLCrypto

#if os(WASI)
  import WASILibc
#endif

@main
enum SHA256BenchmarkCommand {
  private enum ArgumentError: Error {
    case invalidArguments
    case unavailableWASIArguments
    case unavailableWASIClock
  }

  static func main() throws {
    let arguments = try commandLineArguments()
    if (arguments.count == 4 || arguments.count == 5),
      arguments[1] == "--validate"
    {
      guard
        let byteCount = Int(arguments[2]),
        let iterations = Int(arguments[3]),
        let inputOffset = parseInputOffset(arguments),
        byteCount > 0,
        iterations > 0,
        inputOffset <= Int.max - byteCount
      else {
        throw ArgumentError.invalidArguments
      }
      try validate(
        byteCount: byteCount,
        iterations: iterations,
        inputOffset: inputOffset
      )
      return
    }

    guard (arguments.count == 4 || arguments.count == 5),
      let byteCount = Int(arguments[1]),
      let iterations = Int(arguments[2]),
      let warmupIterations = Int(arguments[3]),
      let inputOffset = parseInputOffset(arguments),
      byteCount > 0,
      iterations > 0,
      warmupIterations >= 0,
      inputOffset <= Int.max - byteCount
    else {
      throw ArgumentError.invalidArguments
    }

    var warmupInput = makeInput(
      byteCount: byteCount,
      inputOffset: inputOffset
    )
    var warmupOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)
    _ = try run(
      input: &warmupInput,
      output: &warmupOutput,
      iterations: warmupIterations,
      byteCount: byteCount,
      inputOffset: inputOffset
    )

    var input = makeInput(
      byteCount: byteCount,
      inputOffset: inputOffset
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let checksum: UInt64
    let nanoseconds: UInt64
    #if os(WASI)
      let start = try wasiMonotonicNanoseconds()
      checksum = try run(
        input: &input,
        output: &output,
        iterations: iterations,
        byteCount: byteCount,
        inputOffset: inputOffset
      )
      let end = try wasiMonotonicNanoseconds()
      guard end >= start else {
        throw ArgumentError.unavailableWASIClock
      }
      nanoseconds = end - start
    #else
      let clock = ContinuousClock()
      let start = clock.now
      checksum = try run(
        input: &input,
        output: &output,
        iterations: iterations,
        byteCount: byteCount,
        inputOffset: inputOffset
      )
      let elapsed = start.duration(to: clock.now).components
      guard elapsed.seconds >= 0, elapsed.attoseconds >= 0 else {
        throw ArgumentError.unavailableWASIClock
      }
      nanoseconds =
        UInt64(elapsed.seconds) * 1_000_000_000
        + UInt64(elapsed.attoseconds) / 1_000_000_000
    #endif

    print("RESULT,\(nanoseconds),\(checksum),\(hexString(output.span))")
  }

  private static func validate(
    byteCount: Int,
    iterations: Int,
    inputOffset: Int
  ) throws(CryptoInputError) {
    var input = makeInput(
      byteCount: byteCount,
      inputOffset: inputOffset
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var inputSpan = input.mutableSpan
    var outputSpan = output.mutableSpan
    var iteration = 0
    while iteration < iterations {
      inputSpan[inputOffset] = UInt8(truncatingIfNeeded: iteration)
      try SHA256.hash(
        inputSpan.span.extracting(
          inputOffset..<(inputOffset + byteCount)
        ),
        into: &outputSpan
      )
      print("DIGEST,\(iteration),\(hexString(outputSpan.span))")
      iteration += 1
    }
  }

  private static func parseInputOffset(_ arguments: [String]) -> Int? {
    guard arguments.count == 5 else {
      return 0
    }
    guard let inputOffset = Int(arguments[4]), inputOffset >= 0 else {
      return nil
    }
    return inputOffset
  }

  private static func commandLineArguments() throws -> [String] {
    #if hasFeature(Embedded) && os(WASI)
      var argumentCount: UInt = 0
      var bufferSize: UInt = 0
      guard __wasi_args_sizes_get(&argumentCount, &bufferSize) == 0,
        argumentCount <= UInt(Int.max),
        bufferSize <= UInt(Int.max)
      else {
        throw ArgumentError.unavailableWASIArguments
      }

      var argumentPointers = ContiguousArray<UnsafeMutablePointer<UInt8>?>(
        repeating: nil,
        count: Swift.max(1, Int(argumentCount))
      )
      var argumentBuffer = ContiguousArray<UInt8>(
        repeating: 0,
        count: Swift.max(1, Int(bufferSize))
      )

      // Unsafe invariants: WASI initializes at most argumentCount pointers
      // into the bufferSize-byte owner. Both owners remain alive for the
      // complete nested borrow. Each pointer is scanned only to its
      // WASI-provided NUL terminator, no pointer or view escapes the closure,
      // and the resulting Strings own their decoded bytes.
      return try argumentPointers.withUnsafeMutableBufferPointer { pointers in
        try argumentBuffer.withUnsafeMutableBufferPointer { buffer in
          guard
            __wasi_args_get(
              pointers.baseAddress.unsafelyUnwrapped,
              buffer.baseAddress.unsafelyUnwrapped
            ) == 0
          else {
            throw ArgumentError.unavailableWASIArguments
          }

          var arguments = ContiguousArray<String>()
          arguments.reserveCapacity(Int(argumentCount))
          var index = 0
          while index < Int(argumentCount) {
            guard let start = pointers[index] else {
              throw ArgumentError.unavailableWASIArguments
            }
            var end = start
            while end.pointee != 0 {
              end += 1
            }
            arguments.append(
              String(
                decoding: UnsafeBufferPointer(
                  start: start,
                  count: start.distance(to: end)
                ),
                as: UTF8.self
              )
            )
            index += 1
          }
          return Array(arguments)
        }
      }
    #else
      return CommandLine.arguments
    #endif
  }

  #if os(WASI)
    private static func wasiMonotonicNanoseconds() throws(ArgumentError) -> UInt64 {
      var timestamp: __wasi_timestamp_t = 0
      guard
        __wasi_clock_time_get(
          __wasi_clockid_t(1),
          1,
          &timestamp
        ) == 0
      else {
        throw .unavailableWASIClock
      }
      return UInt64(timestamp)
    }
  #endif

  private static func makeInput(
    byteCount: Int,
    inputOffset: Int
  ) -> ContiguousArray<UInt8> {
    var input = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: inputOffset
    )
    input.reserveCapacity(inputOffset + byteCount)
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
    iterations: Int,
    byteCount: Int,
    inputOffset: Int
  ) throws(CryptoInputError) -> UInt64 {
    var inputSpan = input.mutableSpan
    var outputSpan = output.mutableSpan
    var checksum: UInt64 = 0
    var iteration = 0
    while iteration < iterations {
      inputSpan[inputOffset] = UInt8(truncatingIfNeeded: iteration)
      try SHA256.hash(
        inputSpan.span.extracting(
          inputOffset..<(inputOffset + byteCount)
        ),
        into: &outputSpan
      )
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
