extension Field25519 {
  var isZero: Bool {
    let bytes = self.bytes
    var value: UInt8 = 0
    for byte in bytes {
      value |= byte
    }
    return value == 0
  }

  var isNegative: Bool {
    bytes[0] & 1 == 1
  }

  static var edwardsD: Field25519 {
    Field25519(
      bytes: Self.hexBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352").span)
  }

  static var edwardsTwoD: Field25519 {
    Self.edwardsD + Self.edwardsD
  }

  static var edwardsSqrtM1: Field25519 {
    Field25519(
      bytes: Self.hexBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b").span)
  }

  static prefix func - (value: Field25519) -> Field25519 {
    Field25519(constant: 0) - value
  }

  private static func hexBytes(_ string: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(string.utf8.count / 2)
    var high: UInt8 = 0
    var haveHigh = false
    for byte in string.utf8 {
      let value: UInt8
      switch byte {
      case 0x30...0x39: value = byte - 0x30
      case 0x61...0x66: value = byte - 0x61 + 10
      case 0x41...0x46: value = byte - 0x41 + 10
      default: value = 0
      }
      if haveHigh {
        result.append((high << 4) | value)
        haveHigh = false
      } else {
        high = value
        haveHigh = true
      }
    }
    return result
  }
}
