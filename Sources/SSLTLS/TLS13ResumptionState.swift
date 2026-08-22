import SSLCore
import SSLCrypto

/// Single-use resumption state derived from a TLS 1.3 ticket.
///
/// The ticket bytes are an opaque server-selected identity. The state owns the
/// resumption master secret and ticket nonce, validates lifetime and clock
/// ordering, and consumes the PSK exactly once. Ticket persistence and replay
/// coordination across processes remain outside; the TLS handshake engine owns
/// ClientHello binder construction and server-side ticket-age validation.
public struct TLS13ResumptionState: ~Copyable, Sendable {
    public static let maximumTicketByteCount = 16 * 1024
    public static let maximumNonceByteCount = 255

    public let cipherSuite: TLSCipherSuite
    public let issuedAt: VerificationInstant
    public let lifetime: UInt32
    public let ageAdd: UInt32
    public let maximumEarlyDataByteCount: UInt32
    public let applicationProtocol: TLS13ApplicationProtocol?
    package let authenticatedPeerRole: TLSRole?
    package let authenticatedClientCertificate: TLS13ValidatedClientCertificate?

    /// Whether the ticket-issuing endpoint authenticated its peer's
    /// certificate and CertificateVerify proof before issuing this state.
    public var peerCertificateAuthenticated: Bool {
        authenticatedPeerRole != nil
    }

    private let ticket: OwnedBytes
    private let ticketNonce: OwnedBytes
    private let resumptionMasterSecret: SecretBytes
    private var consumed: Bool

    public init(
        ticket: Span<UInt8>,
        ticketNonce: Span<UInt8>,
        resumptionMasterSecret: Span<UInt8>,
        cipherSuite: TLSCipherSuite,
        issuedAt: VerificationInstant,
        lifetime: UInt32,
        ageAdd: UInt32,
        maximumEarlyDataByteCount: UInt32 = 0,
        applicationProtocol: TLS13ApplicationProtocol? = nil
    ) throws(TLS13ResumptionError) {
        try self.init(
            ticket: ticket,
            ticketNonce: ticketNonce,
            resumptionMasterSecret: resumptionMasterSecret,
            cipherSuite: cipherSuite,
            issuedAt: issuedAt,
            lifetime: lifetime,
            ageAdd: ageAdd,
            maximumEarlyDataByteCount: maximumEarlyDataByteCount,
            applicationProtocol: applicationProtocol,
            authenticatedPeerRole: nil
        )
    }

    package init(
        ticket: Span<UInt8>,
        ticketNonce: Span<UInt8>,
        resumptionMasterSecret: Span<UInt8>,
        cipherSuite: TLSCipherSuite,
        issuedAt: VerificationInstant,
        lifetime: UInt32,
        ageAdd: UInt32,
        maximumEarlyDataByteCount: UInt32,
        applicationProtocol: TLS13ApplicationProtocol?,
        authenticatedPeerRole: TLSRole?,
        authenticatedClientCertificate: TLS13ValidatedClientCertificate? = nil
    ) throws(TLS13ResumptionError) {
        guard !ticket.isEmpty, ticket.count <= Self.maximumTicketByteCount else {
            throw .invalidTicketLength(actual: ticket.count)
        }
        guard !ticketNonce.isEmpty, ticketNonce.count <= Self.maximumNonceByteCount else {
            throw .invalidNonceLength(actual: ticketNonce.count)
        }
        guard lifetime > 0 else { throw .invalidLifetime }
        let expectedSecretLength = TLS13KeySchedule.hashByteCount(for: cipherSuite)
        guard resumptionMasterSecret.count == expectedSecretLength else {
            throw .invalidSecretLength(
                expected: expectedSecretLength,
                actual: resumptionMasterSecret.count
            )
        }
        let secret: SecretBytes
        do {
            secret = try SecretBytes(copying: resumptionMasterSecret)
        } catch {
            throw .cryptographicFailure
        }
        self.ticket = OwnedBytes(copying: ticket)
        self.ticketNonce = OwnedBytes(copying: ticketNonce)
        self.resumptionMasterSecret = consume secret
        self.cipherSuite = cipherSuite
        self.issuedAt = issuedAt
        self.lifetime = lifetime
        self.ageAdd = ageAdd
        self.maximumEarlyDataByteCount = maximumEarlyDataByteCount
        self.applicationProtocol = applicationProtocol
        self.authenticatedPeerRole = authenticatedPeerRole
        self.authenticatedClientCertificate = authenticatedClientCertificate
        consumed = false
    }

    public var isConsumed: Bool { consumed }

    public borrowing func withTicketBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(ticket.span)
    }

    /// Returns RFC 8446's obfuscated_ticket_age in milliseconds.
    public func obfuscatedTicketAge(
        at instant: VerificationInstant
    ) throws(TLS13ResumptionError) -> UInt32 {
        guard instant >= issuedAt else { throw .issuedInFuture }
        let elapsedSecondsResult = instant.secondsSinceUnixEpoch.subtractingReportingOverflow(
            issuedAt.secondsSinceUnixEpoch
        )
        guard !elapsedSecondsResult.overflow else { throw .expired }
        let elapsedSeconds = elapsedSecondsResult.partialValue
        guard elapsedSeconds <= Int64(lifetime) else { throw .expired }
        let elapsedMilliseconds = elapsedSeconds.multipliedReportingOverflow(by: 1_000)
        guard !elapsedMilliseconds.overflow else { throw .expired }
        let nanoseconds = Int64(instant.nanoseconds) - Int64(issuedAt.nanoseconds)
        let adjustedMilliseconds: Int64
        if nanoseconds < 0 {
            adjustedMilliseconds = elapsedMilliseconds.partialValue - 1
        } else {
            adjustedMilliseconds = elapsedMilliseconds.partialValue
        }
        guard adjustedMilliseconds >= 0 else { throw .issuedInFuture }
        let lifetimeMilliseconds = UInt64(lifetime) * 1_000
        guard UInt64(adjustedMilliseconds) <= lifetimeMilliseconds else { throw .expired }
        return UInt32(truncatingIfNeeded: UInt64(adjustedMilliseconds) &+ UInt64(ageAdd))
    }

    /// Consumes this state and derives the PSK used by the `pre_shared_key`
    /// extension. A second call fails before touching the secret.
    public mutating func consumePSK() throws(TLS13ResumptionError) -> SecretBytes {
        guard !consumed else { throw .replayDetected }
        consumed = true
        do {
            return try TLS13KeySchedule.deriveResumptionPSK(
                resumptionMasterSecret: resumptionMasterSecret,
                ticketNonce: ticketNonce.span,
                cipherSuite: cipherSuite
            )
        } catch {
            throw .cryptographicFailure
        }
    }

}
