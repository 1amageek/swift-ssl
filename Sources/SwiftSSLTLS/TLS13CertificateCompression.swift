import SwiftSSLCore

public enum TLS13CertificateCompressionAlgorithm: UInt16, Sendable, Hashable {
  public static let extensionType: UInt16 = 27

  case zlib = 1
  case brotli = 2
  case zstd = 3
}

public enum TLS13CertificateCompressionError: Error, Sendable, Equatable {
  case invalidConfiguration
  case invalidZlibHeader
  case unsupportedDictionary
  case malformedDeflateStream
  case outputLimitExceeded(limit: Int)
  case uncompressedLengthMismatch(expected: Int, actual: Int)
  case checksumMismatch
}

public protocol TLS13CertificateCompressing: Sendable {
  var algorithm: TLS13CertificateCompressionAlgorithm { get }

  func compress(
    _ certificateMessage: Span<UInt8>
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes
}

public protocol TLS13CertificateDecompressing: Sendable {
  var algorithm: TLS13CertificateCompressionAlgorithm { get }

  func decompress(
    _ compressedCertificateMessage: Span<UInt8>,
    uncompressedByteCount: Int,
    maximumUncompressedByteCount: Int
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes
}

public protocol TLS13CertificateCompressionCoding:
  TLS13CertificateCompressing,
  TLS13CertificateDecompressing
{}

/// Pure Swift RFC 1950 zlib and RFC 1951 DEFLATE certificate compression.
///
/// Compression emits a fixed-Huffman stream with a bounded one-entry LZ77
/// index. Decompression accepts stored, fixed-Huffman, and dynamic-Huffman
/// streams while enforcing the caller's exact output limit.
public struct TLS13ZlibCertificateCompression:
  TLS13CertificateCompressionCoding,
  Sendable
{
  public let algorithm = TLS13CertificateCompressionAlgorithm.zlib

  public init() {}

  public func compress(
    _ certificateMessage: Span<UInt8>
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes {
    guard certificateMessage.count <= 0x00FF_FFFF else {
      throw .outputLimitExceeded(limit: 0x00FF_FFFF)
    }
    var writer = DeflateBitWriter(
      minimumCapacity: certificateMessage.count + 16
    )
    writer.appendByteAligned(0x78)
    writer.appendByteAligned(0x01)
    writer.writeBits(1, count: 1)
    writer.writeBits(1, count: 2)

    var lastPositionByHash = ContiguousArray<Int32>(
      repeating: -1,
      count: 1 << 16
    )
    var index = 0
    while index < certificateMessage.count {
      var matchLength = 0
      var matchDistance = 0
      if index + 2 < certificateMessage.count {
        let hash = Self.prefixHash(at: index, in: certificateMessage)
        let storedCandidate = lastPositionByHash[hash]
        if storedCandidate >= 0 {
          let candidate = Int(storedCandidate)
          let distance = index - candidate
          if distance > 0, distance <= 32_768 {
            let maximumLength = Swift.min(258, certificateMessage.count - index)
            var length = 0
            while length < maximumLength,
              certificateMessage[candidate + length] == certificateMessage[index + length]
            {
              length += 1
            }
            if length >= 3 {
              matchLength = length
              matchDistance = distance
            }
          }
        }
      }

      if matchLength >= 3 {
        Self.writeLength(matchLength, to: &writer)
        Self.writeDistance(matchDistance, to: &writer)
        var consumed = 0
        while consumed < matchLength {
          let position = index + consumed
          if position + 2 < certificateMessage.count {
            lastPositionByHash[
              Self.prefixHash(at: position, in: certificateMessage)
            ] = Int32(position)
          }
          consumed += 1
        }
        index += matchLength
      } else {
        Self.writeFixedLiteral(Int(certificateMessage[index]), to: &writer)
        if index + 2 < certificateMessage.count {
          lastPositionByHash[
            Self.prefixHash(at: index, in: certificateMessage)
          ] = Int32(index)
        }
        index += 1
      }
    }
    Self.writeFixedLiteral(256, to: &writer)
    writer.alignToByte()
    let checksum = Self.adler32(certificateMessage)
    writer.appendByteAligned(UInt8(truncatingIfNeeded: checksum >> 24))
    writer.appendByteAligned(UInt8(truncatingIfNeeded: checksum >> 16))
    writer.appendByteAligned(UInt8(truncatingIfNeeded: checksum >> 8))
    writer.appendByteAligned(UInt8(truncatingIfNeeded: checksum))
    return writer.finish()
  }

  public func decompress(
    _ compressedCertificateMessage: Span<UInt8>,
    uncompressedByteCount: Int,
    maximumUncompressedByteCount: Int = 0x00FF_FFFF
  ) throws(TLS13CertificateCompressionError) -> OwnedBytes {
    guard uncompressedByteCount >= 0,
      maximumUncompressedByteCount >= 0,
      uncompressedByteCount <= maximumUncompressedByteCount
    else {
      throw .outputLimitExceeded(limit: maximumUncompressedByteCount)
    }
    guard compressedCertificateMessage.count >= 6 else {
      throw .invalidZlibHeader
    }
    let cmf = compressedCertificateMessage[0]
    let flg = compressedCertificateMessage[1]
    guard cmf & 0x0F == 8,
      cmf >> 4 <= 7,
      (Int(cmf) << 8 | Int(flg)).isMultiple(of: 31)
    else {
      throw .invalidZlibHeader
    }
    guard flg & 0x20 == 0 else { throw .unsupportedDictionary }

    let deflateEnd = compressedCertificateMessage.count - 4
    let deflateBytes = compressedCertificateMessage.extracting(2..<deflateEnd)
    var reader = DeflateBitReader(deflateBytes)
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(uncompressedByteCount)
    var isFinalBlock = false
    while !isFinalBlock {
      isFinalBlock = try reader.readBits(count: 1) == 1
      let blockType = try reader.readBits(count: 2)
      switch blockType {
      case 0:
        reader.alignToByte()
        let length = Int(try reader.readBits(count: 16))
        let complement = Int(try reader.readBits(count: 16))
        guard (length ^ 0xFFFF) == complement else {
          throw .malformedDeflateStream
        }
        var copied = 0
        while copied < length {
          try Self.append(
            UInt8(truncatingIfNeeded: reader.readBits(count: 8)),
            to: &output,
            limit: uncompressedByteCount
          )
          copied += 1
        }
      case 1:
        try Self.inflateCompressedBlock(
          reader: &reader,
          literalLengths: Self.fixedLiteralLengths,
          distanceLengths: Self.fixedDistanceLengths,
          output: &output,
          limit: uncompressedByteCount
        )
      case 2:
        let trees = try Self.readDynamicTrees(reader: &reader)
        try Self.inflateCompressedBlock(
          reader: &reader,
          literalLengths: trees.literalLengths,
          distanceLengths: trees.distanceLengths,
          output: &output,
          limit: uncompressedByteCount
        )
      default:
        throw .malformedDeflateStream
      }
    }
    reader.alignToByte()
    guard reader.isAtEnd else { throw .malformedDeflateStream }
    guard output.count == uncompressedByteCount else {
      throw .uncompressedLengthMismatch(
        expected: uncompressedByteCount,
        actual: output.count
      )
    }
    let expectedChecksum =
      UInt32(compressedCertificateMessage[deflateEnd]) << 24
      | UInt32(compressedCertificateMessage[deflateEnd + 1]) << 16
      | UInt32(compressedCertificateMessage[deflateEnd + 2]) << 8
      | UInt32(compressedCertificateMessage[deflateEnd + 3])
    guard Self.adler32(output.span) == expectedChecksum else {
      throw .checksumMismatch
    }
    return OwnedBytes(consuming: output)
  }

  private static let fixedLiteralLengths: ContiguousArray<UInt8> = {
    var lengths = ContiguousArray<UInt8>(repeating: 0, count: 288)
    for index in 0...143 { lengths[index] = 8 }
    for index in 144...255 { lengths[index] = 9 }
    for index in 256...279 { lengths[index] = 7 }
    for index in 280...287 { lengths[index] = 8 }
    return lengths
  }()

  private static let fixedDistanceLengths = ContiguousArray<UInt8>(
    repeating: 5,
    count: 32
  )

  private static let lengthBases: ContiguousArray<Int> = [
    3, 4, 5, 6, 7, 8, 9, 10,
    11, 13, 15, 17,
    19, 23, 27, 31,
    35, 43, 51, 59,
    67, 83, 99, 115,
    131, 163, 195, 227,
    258,
  ]

  private static let lengthExtraBits: ContiguousArray<Int> = [
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1,
    2, 2, 2, 2,
    3, 3, 3, 3,
    4, 4, 4, 4,
    5, 5, 5, 5,
    0,
  ]

  private static let distanceBases: ContiguousArray<Int> = [
    1, 2, 3, 4,
    5, 7, 9, 13,
    17, 25, 33, 49,
    65, 97, 129, 193,
    257, 385, 513, 769,
    1_025, 1_537, 2_049, 3_073,
    4_097, 6_145, 8_193, 12_289,
    16_385, 24_577,
  ]

  private static let distanceExtraBits: ContiguousArray<Int> = [
    0, 0, 0, 0,
    1, 1, 2, 2,
    3, 3, 4, 4,
    5, 5, 6, 6,
    7, 7, 8, 8,
    9, 9, 10, 10,
    11, 11, 12, 12,
    13, 13,
  ]

  private static let codeLengthOrder: ContiguousArray<Int> = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
  ]

  private static func readDynamicTrees(
    reader: inout DeflateBitReader
  ) throws(TLS13CertificateCompressionError) -> (
    literalLengths: ContiguousArray<UInt8>,
    distanceLengths: ContiguousArray<UInt8>
  ) {
    let literalCount = Int(try reader.readBits(count: 5)) + 257
    let distanceCount = Int(try reader.readBits(count: 5)) + 1
    let codeLengthCount = Int(try reader.readBits(count: 4)) + 4
    guard literalCount <= 286, distanceCount <= 32 else {
      throw .malformedDeflateStream
    }
    var codeLengths = ContiguousArray<UInt8>(repeating: 0, count: 19)
    var index = 0
    while index < codeLengthCount {
      codeLengths[codeLengthOrder[index]] = UInt8(
        truncatingIfNeeded: try reader.readBits(count: 3)
      )
      index += 1
    }
    let codeLengthTree = try DeflateHuffmanTree(lengths: codeLengths)
    let totalCount = literalCount + distanceCount
    var lengths = ContiguousArray<UInt8>()
    lengths.reserveCapacity(totalCount)
    while lengths.count < totalCount {
      let symbol = try codeLengthTree.decode(reader: &reader)
      switch symbol {
      case 0...15:
        lengths.append(UInt8(symbol))
      case 16:
        guard let previous = lengths.last else {
          throw .malformedDeflateStream
        }
        let repeatCount = Int(try reader.readBits(count: 2)) + 3
        guard lengths.count + repeatCount <= totalCount else {
          throw .malformedDeflateStream
        }
        for _ in 0..<repeatCount { lengths.append(previous) }
      case 17:
        let repeatCount = Int(try reader.readBits(count: 3)) + 3
        guard lengths.count + repeatCount <= totalCount else {
          throw .malformedDeflateStream
        }
        for _ in 0..<repeatCount { lengths.append(0) }
      case 18:
        let repeatCount = Int(try reader.readBits(count: 7)) + 11
        guard lengths.count + repeatCount <= totalCount else {
          throw .malformedDeflateStream
        }
        for _ in 0..<repeatCount { lengths.append(0) }
      default:
        throw .malformedDeflateStream
      }
    }
    let literalLengths = ContiguousArray(lengths[0..<literalCount])
    let distanceLengths = ContiguousArray(lengths[literalCount..<totalCount])
    guard literalLengths[256] != 0 else {
      throw .malformedDeflateStream
    }
    return (literalLengths, distanceLengths)
  }

  private static func inflateCompressedBlock(
    reader: inout DeflateBitReader,
    literalLengths: borrowing ContiguousArray<UInt8>,
    distanceLengths: borrowing ContiguousArray<UInt8>,
    output: inout ContiguousArray<UInt8>,
    limit: Int
  ) throws(TLS13CertificateCompressionError) {
    let literalTree = try DeflateHuffmanTree(
      lengths: literalLengths,
      allowsSingleSymbolIncompleteTree: true
    )
    let distanceTree = try DeflateHuffmanTree(
      lengths: distanceLengths,
      allowsEmptyTree: true,
      allowsSingleSymbolIncompleteTree: true
    )
    while true {
      let symbol = try literalTree.decode(reader: &reader)
      switch symbol {
      case 0...255:
        try append(UInt8(symbol), to: &output, limit: limit)
      case 256:
        return
      case 257...285:
        let lengthIndex = symbol - 257
        var length = lengthBases[lengthIndex]
        let lengthBits = lengthExtraBits[lengthIndex]
        if lengthBits > 0 {
          length += Int(try reader.readBits(count: lengthBits))
        }
        let distanceSymbol = try distanceTree.decode(reader: &reader)
        guard distanceSymbol < distanceBases.count else {
          throw .malformedDeflateStream
        }
        var distance = distanceBases[distanceSymbol]
        let distanceBits = distanceExtraBits[distanceSymbol]
        if distanceBits > 0 {
          distance += Int(try reader.readBits(count: distanceBits))
        }
        guard distance > 0, distance <= output.count else {
          throw .malformedDeflateStream
        }
        var copied = 0
        while copied < length {
          let byte = output[output.count - distance]
          try append(byte, to: &output, limit: limit)
          copied += 1
        }
      default:
        throw .malformedDeflateStream
      }
    }
  }

  private static func append(
    _ byte: UInt8,
    to output: inout ContiguousArray<UInt8>,
    limit: Int
  ) throws(TLS13CertificateCompressionError) {
    guard output.count < limit else {
      throw .outputLimitExceeded(limit: limit)
    }
    output.append(byte)
  }

  private static func prefixHash(
    at index: Int,
    in input: Span<UInt8>
  ) -> Int {
    let prefix = UInt32(input[index]) << 16
      | UInt32(input[index + 1]) << 8
      | UInt32(input[index + 2])
    return Int((prefix &* 2_654_435_761) >> 16)
  }

  private static func writeLength(
    _ length: Int,
    to writer: inout DeflateBitWriter
  ) {
    var index = 0
    while index + 1 < lengthBases.count,
      length >= lengthBases[index + 1]
    {
      index += 1
    }
    writeFixedLiteral(257 + index, to: &writer)
    let extraBitCount = lengthExtraBits[index]
    if extraBitCount > 0 {
      writer.writeBits(
        UInt32(length - lengthBases[index]),
        count: extraBitCount
      )
    }
  }

  private static func writeDistance(
    _ distance: Int,
    to writer: inout DeflateBitWriter
  ) {
    var index = 0
    while index + 1 < distanceBases.count,
      distance >= distanceBases[index + 1]
    {
      index += 1
    }
    writer.writeCanonicalCode(UInt32(index), bitCount: 5)
    let extraBitCount = distanceExtraBits[index]
    if extraBitCount > 0 {
      writer.writeBits(
        UInt32(distance - distanceBases[index]),
        count: extraBitCount
      )
    }
  }

  private static func writeFixedLiteral(
    _ symbol: Int,
    to writer: inout DeflateBitWriter
  ) {
    switch symbol {
    case 0...143:
      writer.writeCanonicalCode(UInt32(0x30 + symbol), bitCount: 8)
    case 144...255:
      writer.writeCanonicalCode(UInt32(0x190 + symbol - 144), bitCount: 9)
    case 256...279:
      writer.writeCanonicalCode(UInt32(symbol - 256), bitCount: 7)
    default:
      writer.writeCanonicalCode(UInt32(0xC0 + symbol - 280), bitCount: 8)
    }
  }

  private static func adler32(_ bytes: Span<UInt8>) -> UInt32 {
    let modulus: UInt32 = 65_521
    var first: UInt32 = 1
    var second: UInt32 = 0
    var index = 0
    while index < bytes.count {
      let end = Swift.min(index + 5_552, bytes.count)
      while index < end {
        first += UInt32(bytes[index])
        second += first
        index += 1
      }
      first %= modulus
      second %= modulus
    }
    return second << 16 | first
  }
}

private struct DeflateBitReader: ~Escapable {
  private let bytes: Span<UInt8>
  private var byteIndex: Int
  private var bitIndex: Int

  @_lifetime(copy bytes)
  init(_ bytes: Span<UInt8>) {
    self.bytes = bytes
    byteIndex = 0
    bitIndex = 0
  }

  var isAtEnd: Bool { byteIndex == bytes.count && bitIndex == 0 }

  mutating func readBits(
    count: Int
  ) throws(TLS13CertificateCompressionError) -> UInt32 {
    guard count >= 0, count <= 16 else {
      throw .malformedDeflateStream
    }
    var value: UInt32 = 0
    var outputBit = 0
    while outputBit < count {
      guard byteIndex < bytes.count else {
        throw .malformedDeflateStream
      }
      let bit = (bytes[byteIndex] >> bitIndex) & 1
      value |= UInt32(bit) << outputBit
      outputBit += 1
      bitIndex += 1
      if bitIndex == 8 {
        bitIndex = 0
        byteIndex += 1
      }
    }
    return value
  }

  mutating func alignToByte() {
    if bitIndex != 0 {
      bitIndex = 0
      byteIndex += 1
    }
  }
}

private struct DeflateHuffmanTree {
  private let counts: ContiguousArray<Int>
  private let symbols: ContiguousArray<Int>
  private let maximumBitCount: Int

  init(
    lengths: borrowing ContiguousArray<UInt8>,
    allowsEmptyTree: Bool = false,
    allowsSingleSymbolIncompleteTree: Bool = false
  ) throws(TLS13CertificateCompressionError) {
    var counts = ContiguousArray<Int>(repeating: 0, count: 16)
    var maximumBitCount = 0
    var lengthIndex = 0
    while lengthIndex < lengths.count {
      let length = lengths[lengthIndex]
      guard length <= 15 else { throw .malformedDeflateStream }
      if length > 0 {
        counts[Int(length)] += 1
        maximumBitCount = Swift.max(maximumBitCount, Int(length))
      }
      lengthIndex += 1
    }
    if maximumBitCount == 0 {
      guard allowsEmptyTree else { throw .malformedDeflateStream }
      self.counts = counts
      self.symbols = []
      self.maximumBitCount = 0
      return
    }
    var remaining = 1
    for bitCount in 1...15 {
      remaining = remaining * 2 - counts[bitCount]
      guard remaining >= 0 else { throw .malformedDeflateStream }
    }
    guard remaining == 0
      || (allowsSingleSymbolIncompleteTree
        && maximumBitCount == 1
        && counts[1] == 1)
    else {
      throw .malformedDeflateStream
    }
    var offsets = ContiguousArray<Int>(repeating: 0, count: 16)
    for bitCount in 1..<15 {
      offsets[bitCount + 1] = offsets[bitCount] + counts[bitCount]
    }
    var mutableOffsets = offsets
    var symbols = ContiguousArray<Int>(repeating: 0, count: lengths.count)
    var symbol = 0
    while symbol < lengths.count {
      let length = Int(lengths[symbol])
      if length > 0 {
        symbols[mutableOffsets[length]] = symbol
        mutableOffsets[length] += 1
      }
      symbol += 1
    }
    self.counts = counts
    self.symbols = symbols
    self.maximumBitCount = maximumBitCount
  }

  func decode(
    reader: inout DeflateBitReader
  ) throws(TLS13CertificateCompressionError) -> Int {
    guard maximumBitCount > 0 else { throw .malformedDeflateStream }
    var code = 0
    var first = 0
    var symbolIndex = 0
    for bitCount in 1...maximumBitCount {
      code |= Int(try reader.readBits(count: 1))
      let count = counts[bitCount]
      if code < first + count {
        return symbols[symbolIndex + code - first]
      }
      symbolIndex += count
      first = (first + count) << 1
      code <<= 1
    }
    throw .malformedDeflateStream
  }
}

private struct DeflateBitWriter {
  private var bytes: ContiguousArray<UInt8>
  private var pendingByte: UInt8
  private var pendingBitCount: Int

  init(minimumCapacity: Int) {
    bytes = []
    bytes.reserveCapacity(minimumCapacity)
    pendingByte = 0
    pendingBitCount = 0
  }

  mutating func writeBits(_ value: UInt32, count: Int) {
    var bitIndex = 0
    while bitIndex < count {
      let bit = UInt8(truncatingIfNeeded: value >> bitIndex) & 1
      pendingByte |= bit << pendingBitCount
      pendingBitCount += 1
      bitIndex += 1
      if pendingBitCount == 8 {
        bytes.append(pendingByte)
        pendingByte = 0
        pendingBitCount = 0
      }
    }
  }

  mutating func writeCanonicalCode(_ code: UInt32, bitCount: Int) {
    var reversed: UInt32 = 0
    var index = 0
    while index < bitCount {
      reversed = reversed << 1 | ((code >> index) & 1)
      index += 1
    }
    writeBits(reversed, count: bitCount)
  }

  mutating func alignToByte() {
    if pendingBitCount > 0 {
      bytes.append(pendingByte)
      pendingByte = 0
      pendingBitCount = 0
    }
  }

  mutating func appendByteAligned(_ byte: UInt8) {
    precondition(pendingBitCount == 0)
    bytes.append(byte)
  }

  consuming func finish() -> OwnedBytes {
    precondition(pendingBitCount == 0)
    return OwnedBytes(consuming: bytes)
  }
}
