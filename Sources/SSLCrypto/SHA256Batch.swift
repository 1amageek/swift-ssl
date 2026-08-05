import SSLCore

extension SHA256: BatchHashFunction {
  public static var preferredBatchWidth: Int {
    #if os(macOS) && arch(arm64) && canImport(simd)
      2
    #else
      1
    #endif
  }

  public static func hashBatch(
    _ inputStorage: Span<UInt8>,
    inputs: Span<HashBatchInput>,
    into output: inout MutableSpan<UInt8>
  ) throws(BatchHashError) {
    let (expectedOutputByteCount, outputLengthOverflow) =
      inputs.count.multipliedReportingOverflow(by: digestByteCount)
    guard !outputLengthOverflow else {
      throw .outputLengthOverflow
    }
    guard output.count == expectedOutputByteCount else {
      throw .invalidOutputLength(
        expected: expectedOutputByteCount,
        actual: output.count
      )
    }
    guard !spansOverlap(inputStorage, output.span) else {
      throw .overlappingInputAndOutput
    }

    var inputIndex = 0
    while inputIndex < inputs.count {
      let input = inputs[inputIndex]
      guard input.offset >= 0, input.byteCount >= 0,
        input.offset <= inputStorage.count,
        input.byteCount <= inputStorage.count - input.offset
      else {
        throw .invalidInputRange(index: inputIndex)
      }
      guard UInt64(input.byteCount) <= SHA256Context.maximumInputByteCount else {
        throw .inputTooLong(
          index: inputIndex,
          limit: SHA256Context.maximumInputByteCount
        )
      }
      inputIndex += 1
    }

    inputIndex = 0
    while inputIndex < inputs.count {
      let first = inputs[inputIndex]
      let firstInput = inputStorage.extracting(
        first.offset..<(first.offset + first.byteCount)
      )
      let firstOutputStart = inputIndex * digestByteCount

      #if os(macOS) && arch(arm64) && canImport(simd)
        if inputIndex + 1 < inputs.count {
          let second = inputs[inputIndex + 1]
          if first.byteCount == second.byteCount {
            let secondInput = inputStorage.extracting(
              second.offset..<(second.offset + second.byteCount)
            )
            var pairOutput = output._mutatingExtracting(
              firstOutputStart..<(firstOutputStart + digestByteCount * 2)
            )
            do {
              try SHA256Pair.hash(
                firstInput,
                secondInput,
                into: &pairOutput
              )
            } catch let error {
              throw .primitiveFailure(index: inputIndex, error: error)
            }
            inputIndex += 2
            continue
          }
        }
      #endif

      var firstOutput = output._mutatingExtracting(
        firstOutputStart..<(firstOutputStart + digestByteCount)
      )
      do {
        try hash(firstInput, into: &firstOutput)
      } catch let error {
        throw .primitiveFailure(index: inputIndex, error: error)
      }
      inputIndex += 1
    }
  }

  private static func spansOverlap(
    _ first: Span<UInt8>,
    _ second: Span<UInt8>
  ) -> Bool {
    guard !first.isEmpty, !second.isEmpty else {
      return false
    }

    // Unsafe invariants: both spans borrow initialized byte storage for these
    // synchronous closures and neither pointer escapes. Checked address
    // addition treats an impossible wrapped range as overlapping. The helper
    // reads addresses only and does not bind, rebind, or mutate memory.
    return first.withUnsafeBufferPointer { firstBuffer in
      second.withUnsafeBufferPointer { secondBuffer in
        let firstStart = UInt(bitPattern: firstBuffer.baseAddress!)
        let secondStart = UInt(bitPattern: secondBuffer.baseAddress!)
        let (firstEnd, firstOverflow) = firstStart.addingReportingOverflow(
          UInt(firstBuffer.count)
        )
        let (secondEnd, secondOverflow) = secondStart.addingReportingOverflow(
          UInt(secondBuffer.count)
        )
        guard !firstOverflow, !secondOverflow else {
          return true
        }
        return firstStart < secondEnd && secondStart < firstEnd
      }
    }
  }
}
