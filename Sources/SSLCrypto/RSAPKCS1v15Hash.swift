import SSLCore

/// SHA-2 digest algorithms accepted by RSA PKCS #1 v1.5 verification.
public enum RSAPKCS1v15Hash: Sendable, Hashable {
  case sha256
  case sha384
  case sha512

  public var digestByteCount: Int {
    switch self {
    case .sha256: return SHA256.digestByteCount
    case .sha384: return SHA384.digestByteCount
    case .sha512: return SHA512.digestByteCount
    }
  }

  var digestInfoPrefixByteCount: Int { 19 }

  func digestInfoPrefixByte(at index: Int) -> UInt8 {
    precondition(index >= 0 && index < digestInfoPrefixByteCount)
    switch index {
    case 0: return 0x30
    case 1:
      switch self {
      case .sha256: return 0x31
      case .sha384: return 0x41
      case .sha512: return 0x51
      }
    case 2: return 0x30
    case 3: return 0x0D
    case 4: return 0x06
    case 5: return 0x09
    case 6: return 0x60
    case 7: return 0x86
    case 8: return 0x48
    case 9: return 0x01
    case 10: return 0x65
    case 11: return 0x03
    case 12: return 0x04
    case 13: return 0x02
    case 14:
      switch self {
      case .sha256: return 0x01
      case .sha384: return 0x02
      case .sha512: return 0x03
      }
    case 15: return 0x05
    case 16: return 0x00
    case 17: return 0x04
    case 18:
      switch self {
      case .sha256: return 0x20
      case .sha384: return 0x30
      case .sha512: return 0x40
      }
    default: preconditionFailure("validated DigestInfo prefix index")
    }
  }
}
