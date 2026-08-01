import SwiftSSLCrypto

/// One HPKE KDF/AEAD pair carried by an RFC 9849 ECH configuration.
public struct ECHCipherSuite: Sendable, Hashable {
  public let kdfIdentifier: UInt16
  public let aeadIdentifier: UInt16

  public init(kdf: HPKEKDF, aead: HPKEAEAD) {
    kdfIdentifier = Self.identifier(for: kdf)
    aeadIdentifier = Self.identifier(for: aead)
  }

  public init(kdfIdentifier: UInt16, aeadIdentifier: UInt16) {
    self.kdfIdentifier = kdfIdentifier
    self.aeadIdentifier = aeadIdentifier
  }

  public var kdf: HPKEKDF? {
    switch kdfIdentifier {
    case 0x0001: return .sha256
    case 0x0002: return .sha384
    case 0x0003: return .sha512
    default: return nil
    }
  }

  public var aead: HPKEAEAD? {
    switch aeadIdentifier {
    case 0x0001: return .aes128GCM
    case 0x0002: return .aes256GCM
    case 0x0003: return .chaCha20Poly1305
    default: return nil
    }
  }

  public var isSupported: Bool {
    kdf != nil && aead != nil
  }

  private static func identifier(for kdf: HPKEKDF) -> UInt16 {
    switch kdf {
    case .sha256: return 0x0001
    case .sha384: return 0x0002
    case .sha512: return 0x0003
    }
  }

  private static func identifier(for aead: HPKEAEAD) -> UInt16 {
    switch aead {
    case .aes128GCM: return 0x0001
    case .aes256GCM: return 0x0002
    case .chaCha20Poly1305: return 0x0003
    }
  }
}
