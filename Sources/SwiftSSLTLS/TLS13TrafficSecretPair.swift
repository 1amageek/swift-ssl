import SwiftSSLCore
import SwiftSSLCrypto

/// One owned client/server traffic-secret pair at a TLS 1.3 encryption epoch.
///
/// Secret storage is never exposed directly. Public consumers borrow each
/// value inside a scoped closure; package adapters may move each value exactly
/// once into a transport-specific owner.
public struct TLS13TrafficSecretPair: ~Copyable, Sendable {
    public let cipherSuite: TLSCipherSuite
    private var clientSecret: SecretBytes?
    private var serverSecret: SecretBytes?

    package init(
        cipherSuite: TLSCipherSuite,
        clientSecret: consuming SecretBytes,
        serverSecret: consuming SecretBytes
    ) {
        self.cipherSuite = cipherSuite
        self.clientSecret = consume clientSecret
        self.serverSecret = consume serverSecret
    }

    public borrowing func withClientSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        precondition(clientSecret != nil, "The client traffic secret was already consumed")
        return try clientSecret!.withBorrowedBytes(body)
    }

    public borrowing func withServerSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        precondition(serverSecret != nil, "The server traffic secret was already consumed")
        return try serverSecret!.withBorrowedBytes(body)
    }

    package mutating func takeClientSecret() -> SecretBytes? {
        clientSecret.take()
    }

    package mutating func takeServerSecret() -> SecretBytes? {
        serverSecret.take()
    }
}
