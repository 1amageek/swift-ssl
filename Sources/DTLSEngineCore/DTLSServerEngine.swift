/// The Embedded-clean, sans-IO DTLS 1.2 SERVER connection engine.
///
/// `DTLSServerEngine` is the complete server-side DTLS mechanism. It is a value type,
/// caller-locked, sans-IO — the mirror of ``DTLSClientEngine``. The server takes the
/// client's transport address through `receive(_:from:)` for the HelloVerifyRequest
/// cookie binding (RFC 6347 §4.2.1).
///
/// ```
///   receive(ClientHello, from: addr)
///                 ─► DTLSServerHandshake.ingestClientHello
///                 ─► .needCookie → mint cookie (injected HMAC) → HelloVerifyRequest
///                 ─► .verifyCookie → verify cookie (injected HMAC, fail-closed)
///                                  → select suite + sign ServerKeyExchange (injected)
///                                  → serverFlight(acceptingCookieFrom:) → server flight
///   receive(Cert / CKE / CertVerify / Finished)
///                 ─► drive ingest* (ECDHE agree, client CertificateVerify verify,
///                    Finished MAC + client-cert policy in-core, fail-closed)
/// ```
///
/// The handshake FSM core owns the transcript + key schedule + Finished MAC +
/// message_seq ordering + the cookie fail-closed rule + the
/// `requireClientCertificate` policy. The engine owns the record layer + flights +
/// reassembly + cipher-suite selection. ECDHE / signing / verification / cookie
/// HMAC are INJECTED (see ``DTLSEngineConfiguration``); X.509 never enters here.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`, no
/// concrete crypto, no X509; typed throws (`DTLSEngineError`); bare `catch { switch }`.

import NetworkingCore
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore
import DTLSRecordCore

public struct DTLSServerEngine: Sendable {

    let configuration: DTLSEngineConfiguration

    // MARK: - Handshake FSM (the core)

    var fsm: DTLSServerHandshake

    /// Our ECDHE private-key handle (set when building the server flight).
    var keyExchangeHandle: [UInt8]?
    var keyExchangeGroup: NamedGroup?

    // MARK: - Record layer + flight + reassembly (driver-owned)

    var record: DTLSRecordEngine
    var flights: DTLSFlightController
    var reassembly: HandshakeReassemblyBuffer

    var pendingKeyBlock: DTLSKeyBlockCore?
    var negotiatedCipherSuite: DTLSCipherSuite?

    // MARK: - Connection lifecycle

    enum Phase: Sendable, Equatable {
        case start
        case handshaking
        case connected
        case closed
        case failed
    }
    var phase: Phase

    /// The peer (client) certificate DER, surfaced after the Certificate message.
    public internal(set) var remoteCertificateDER: [UInt8]?

    /// The validated peer identifier (e.g. libp2p PeerID) from `validateCertificate`.
    var validatedPeerIdentifier: [UInt8]?

    var isProcessing: Bool

    static var maxBufferSize: Int { 256 * 1024 }

    // MARK: - Initialization

    public init(configuration: DTLSEngineConfiguration) throws(DTLSEngineError) {
        // A server requires identity + all crypto seams incl. the cookie HMAC.
        guard let prfContext = configuration.prfContext,
              let transcriptContext = configuration.transcriptContext,
              configuration.ecdheGenerate != nil, configuration.ecdheAgree != nil,
              configuration.sign != nil, configuration.signingScheme != nil,
              configuration.verifyPeerSignature != nil, configuration.randomBytes != nil,
              configuration.makeCookie != nil, configuration.verifyCookie != nil,
              configuration.recordProtectorFactory != nil else {
            throw .invalidConfiguration(reason: "DTLS server requires identity + crypto seams (PRF/transcript/ecdhe/sign/verify/random/cookie/record protection)")
        }
        guard !configuration.certificateChainDER.isEmpty else {
            throw .invalidConfiguration(reason: "DTLS server requires a certificate")
        }
        try DTLSSRTPNegotiation.validate(configuration.srtpProtectionProfiles)
        self.configuration = configuration
        self.fsm = DTLSServerHandshake(
            requireClientCertificate: configuration.requireClientCertificate,
            prfContext: prfContext,
            transcriptContext: transcriptContext
        )
        self.keyExchangeHandle = nil
        self.keyExchangeGroup = nil
        self.record = DTLSRecordEngine()
        self.flights = DTLSFlightController()
        self.reassembly = HandshakeReassemblyBuffer()
        self.pendingKeyBlock = nil
        self.negotiatedCipherSuite = nil
        self.phase = .start
        self.remoteCertificateDER = nil
        self.validatedPeerIdentifier = nil
        self.isProcessing = false
    }

    // MARK: - Accessors

    public var isEstablished: Bool { phase == .connected }
    public var isClosed: Bool { phase == .closed }
    /// Current caller-driven retransmission token and delay.
    public var retransmissionState: DTLSEngineRetransmissionState {
        flights.retransmissionState
    }
    public var peerIdentifier: [UInt8]? { validatedPeerIdentifier }
    /// The SRTP profile authenticated by the completed DTLS handshake.
    public var negotiatedSRTPProfile: SRTPProtectionProfile? {
        guard phase == .connected else { return nil }
        return fsm.negotiatedSRTPProfile
    }

    /// RFC 5705 key exporter, available only after the handshake completes.
    public func exportKeyingMaterial(
        label: String,
        context: [UInt8]?,
        length: Int
    ) throws(DTLSEngineError) -> [UInt8] {
        guard phase == .connected else { throw .handshakeNotComplete }
        do {
            return try fsm.exportKeyingMaterial(label: label, context: context, length: length)
        } catch {
            throw .from(core: error)
        }
    }

    // MARK: - startHandshake

    /// A server has nothing to send until the first ClientHello arrives.
    public mutating func startHandshake() throws(DTLSEngineError) -> [[UInt8]] {
        guard phase == .start else { throw .handshakeAlreadyStarted }
        phase = .handshaking
        return []
    }

    // MARK: - send / close / handleTimeout

    public mutating func send(_ application: Span<UInt8>) throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { throw .connectionClosed }
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase == .connected else { throw .handshakeNotComplete }
        return try record.encodeRecord(contentType: .applicationData, plaintext: application)
    }

    public mutating func close() throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { return [] }
        phase = .closed
        flights.stop()
        let alertBytes: [UInt8] = [1, 0] // close_notify (warning, 0)
        return try record.encodeRecord(contentType: .alert, plaintext: alertBytes.span)
    }

    public mutating func handleTimeout(
        generation: UInt64
    ) throws(DTLSEngineError) -> DTLSEngineTimeoutResult {
        let current = flights.retransmissionState
        guard phase != .closed, phase != .failed else {
            return .superseded(current: current)
        }
        do {
            switch try flights.prepareTimeout(generation: generation) {
            case .superseded:
                return .superseded(current: flights.retransmissionState)
            case .retransmit(let recipe):
                let datagrams = try encodeDTLSFlight(recipe, using: &record)
                return .retransmit(
                    datagrams: datagrams,
                    next: flights.retransmissionState
                )
            }
        } catch {
            flights.stop()
            phase = .failed
            throw error
        }
    }

    /// Compatibility entry point for a single, serialized timer owner.
    /// Generation-aware drivers should call `handleTimeout(generation:)`.
    @available(*, deprecated, message: "Use handleTimeout(generation:) to reject stale timers")
    public mutating func handleTimeout() throws(DTLSEngineError) -> [[UInt8]] {
        let generation = flights.retransmissionState.generation
        switch try handleTimeout(generation: generation) {
        case .retransmit(let datagrams, _): return datagrams
        case .superseded: return []
        }
    }

    // MARK: - Cipher-suite selection (mirrors the host adapter)

    func selectCipherSuite(from offered: [DTLSCipherSuite]) -> DTLSCipherSuite? {
        for suite in configuration.supportedCipherSuites where offered.contains(suite) {
            return suite
        }
        return nil
    }
}
