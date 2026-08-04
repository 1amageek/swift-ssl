/// The intentionally narrow DTLS 1.2 profile used by WebRTC transports.
///
/// This type is a capability boundary, not a generic TLS-version switch. The
/// profile only admits the protocol features that the WebRTC handshake layer is
/// required to negotiate. Stream TLS and DTLS 1.3 remain owned by their own
/// targets and are not pulled into this target.
public struct DTLS12WebRTCProfile: Sendable, Hashable {
  public static let version: UInt16 = 0xFEFD
  public static let maximumPlaintextByteCount = 16_384
  public static let aes128GCMCipherSuite: UInt16 = 0xC02F
  public static let aes256GCMCipherSuite: UInt16 = 0xC030

  public let cipherSuite: UInt16

  public init(cipherSuite: UInt16) throws(DTLS12ProfileError) {
    guard cipherSuite == Self.aes128GCMCipherSuite ||
      cipherSuite == Self.aes256GCMCipherSuite else {
      throw .unsupportedCipherSuite(cipherSuite)
    }
    self.cipherSuite = cipherSuite
  }

  public var keyByteCount: Int {
    cipherSuite == Self.aes128GCMCipherSuite ? 16 : 32
  }
}

public enum DTLS12ProfileError: Error, Sendable, Equatable {
  case unsupportedCipherSuite(UInt16)
}
