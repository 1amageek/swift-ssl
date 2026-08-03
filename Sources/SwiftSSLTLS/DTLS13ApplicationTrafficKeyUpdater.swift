import SwiftSSLCore

enum DTLS13ApplicationTrafficKeyUpdater {
  static func makeProtector(
    _ secret: borrowing TLS13TrafficSecret,
    epoch: UInt64,
    connectionID: borrowing OwnedBytes
  ) throws(DTLS13ConnectionError) -> RFC9147DTLS13RecordProtector {
    do {
      return try secret.withBorrowedSecret {
        bytes throws(DTLS13RecordError) in
        try RFC9147DTLS13RecordProtector(
          cipherSuite: secret.cipherSuite,
          trafficSecret: bytes,
          epoch: epoch,
          connectionID: connectionID.isEmpty ? nil : connectionID.span
        )
      }
    } catch let error {
      throw .record(error)
    }
  }
}
