import SSLCore

public struct TLS13EncryptedExtensions: Sendable, Hashable {
  public let applicationProtocol: TLS13ApplicationProtocol?
  public let peerTransportParameters: OwnedBytes?
  public let useSRTP: DTLSSRTPUseSRTPData?
  public let echRetryConfigurations: ECHConfigList?
  public let acceptsEarlyData: Bool
  public let clientCertificateType: TLS13CertificateType?
  public let serverCertificateType: TLS13CertificateType?

  public init(
    applicationProtocol: TLS13ApplicationProtocol? = nil,
    peerTransportParameters: OwnedBytes? = nil,
    echRetryConfigurations: ECHConfigList? = nil,
    acceptsEarlyData: Bool = false,
    clientCertificateType: TLS13CertificateType? = nil,
    serverCertificateType: TLS13CertificateType? = nil
  ) {
    self.applicationProtocol = applicationProtocol
    self.peerTransportParameters = peerTransportParameters
    useSRTP = nil
    self.echRetryConfigurations = echRetryConfigurations
    self.acceptsEarlyData = acceptsEarlyData
    self.clientCertificateType = clientCertificateType
    self.serverCertificateType = serverCertificateType
  }

  package init(
    applicationProtocol: TLS13ApplicationProtocol?,
    peerTransportParameters: OwnedBytes?,
    useSRTP: DTLSSRTPUseSRTPData?,
    echRetryConfigurations: ECHConfigList?,
    acceptsEarlyData: Bool,
    clientCertificateType: TLS13CertificateType?,
    serverCertificateType: TLS13CertificateType?
  ) {
    self.applicationProtocol = applicationProtocol
    self.peerTransportParameters = peerTransportParameters
    self.useSRTP = useSRTP
    self.echRetryConfigurations = echRetryConfigurations
    self.acceptsEarlyData = acceptsEarlyData
    self.clientCertificateType = clientCertificateType
    self.serverCertificateType = serverCertificateType
  }
}
