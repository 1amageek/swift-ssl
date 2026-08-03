/// Modern DTLS-SRTP protection profiles from RFC 7714.
public enum DTLSSRTPProtectionProfile: UInt16, Sendable, Hashable {
  case aeadAES128GCM = 0x0007
  case aeadAES256GCM = 0x0008

  public var masterKeyByteCount: Int {
    switch self {
    case .aeadAES128GCM: 16
    case .aeadAES256GCM: 32
    }
  }

  public var masterSaltByteCount: Int { 12 }

  public var exporterByteCount: Int {
    2 * (masterKeyByteCount + masterSaltByteCount)
  }
}
