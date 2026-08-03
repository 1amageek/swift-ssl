import SwiftSSLCore

public protocol DTLS13ClientHandshaking: Sendable, ~Copyable {
  var isEstablished: Bool { get }
  var isHandshakeConfirmed: Bool { get }
  var negotiatedApplicationProtocol: TLS13ApplicationProtocol? { get }
  var receivedTransportParameters: OwnedBytes? { get }
  var srtpProtectionProfile: DTLSSRTPProtectionProfile? { get }
  var srtpMasterKeyIdentifier: OwnedBytes? { get }

  mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(DTLS13ConnectionError)

  mutating func start() throws(DTLS13ConnectionError) -> DTLSActionBatch

  mutating func receiveDatagram(
    _ datagram: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch

  mutating func receiveDatagramStep(
    _ datagram: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition

  mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition

  mutating func sendApplicationData(
    _ content: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch

  mutating func exportSRTPKeyingMaterial()
    throws(DTLS13ConnectionError) -> DTLSSRTPKeyingMaterial

  mutating func requestKeyUpdate(
    requestPeerUpdate: Bool
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch

  mutating func retransmissionTimerExpired()
    throws(DTLS13ConnectionError) -> DTLSActionBatch
}
