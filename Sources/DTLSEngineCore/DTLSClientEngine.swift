/// The Embedded-clean, sans-IO DTLS 1.2 CLIENT connection engine.
///
/// `DTLSClientEngine` is the complete client-side DTLS mechanism. It is a **value
/// type**, **caller-locked** (the facade holds it under its own `Mutex`; the engine
/// itself takes `mutating` methods and never reaches for a lock), and **sans-IO**
/// (the caller does the UDP I/O):
///
/// ```
/// var e = try DTLSClientEngine(configuration: cfg)
/// let hello = try e.startHandshake()           // → [ClientHello datagram]
/// let out   = try e.receive(peer.span)         // → flight datagrams / app data / done
/// let recs  = try e.send(appData.span)         // → one encrypted datagram
/// let again = try e.handleTimeout()            // → retransmit the last flight
/// let bye   = try e.close()                    // → close_notify datagram
/// ```
///
/// ## What it drives (the ENGINE PATTERN)
///
/// ```
///   receive(Span) ─► DTLSRecordEngine.decodeRecord   (one record at a time, decrypt)
///                 ─► HandshakeReassemblyBuffer        (fragment offset/length reassembly)
///                 ─► dispatch each complete message to the cored FSM:
///                       DTLSClientHandshake  (HVR/SH/Cert/SKE/SHD/Finished)
///                 ─► satisfy the FSM's crypto requests via the injected closures
///                    (ECDHE agree, verify SKE sig, sign CertificateVerify)
///                 ─► translate [DTLSCoreAction] → record bytes (encrypt at epoch)
///   send(Span)    ─► encrypt application data via the write protector
///   handleTimeout ─► retransmit the last flight (caller-driven; no clock here)
/// ```
///
/// The handshake FSM core owns the transcript + key schedule + Finished MAC +
/// message_seq ordering/dedup + the HelloVerifyRequest transcript reset. The engine
/// owns the record layer (epoch + 48-bit seq + anti-replay + AEAD), the
/// fragment-reassembly buffer, and the flight controller. ECDHE / signature
/// verification / signing are INJECTED (see ``DTLSEngineConfiguration``); X.509
/// never enters here.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`, no
/// concrete crypto, no X509; typed throws (`DTLSEngineError`); bare `catch { switch }`.

import NetworkingCore
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore
import DTLSRecordCore

public struct DTLSClientEngine: Sendable {

    // Stored state is `internal` (not `private`) so the `+Handshake` extension that
    // implements the dispatch can mutate it. The type stays a value type; the
    // facade holds it under its own lock (caller-locked).

    let configuration: DTLSEngineConfiguration

    // MARK: - Handshake FSM (the core)

    var fsm: DTLSClientHandshake

    /// Our ECDHE private-key handle (set on ServerHelloDone, opaque to the engine).
    var keyExchangeHandle: [UInt8]?
    var keyExchangeGroup: NamedGroup?
    /// The original ClientHello random, reused for the cookie retry.
    var clientRandom: [UInt8]?

    // MARK: - Record layer + flight + reassembly (driver-owned, caller-locked)

    var record: DTLSRecordEngine
    var flights: DTLSFlightController
    var reassembly: HandshakeReassemblyBuffer

    /// The pending key block from the FSM (installed at the CCS boundaries).
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

    /// The peer (server) certificate DER, surfaced after the Certificate message.
    public internal(set) var remoteCertificateDER: [UInt8]?

    /// The validated peer identifier (e.g. libp2p PeerID) from `validateCertificate`.
    var validatedPeerIdentifier: [UInt8]?

    /// Re-entrancy guard mirroring the host `DTLSConnection.isProcessing`.
    var isProcessing: Bool

    static var maxBufferSize: Int { 256 * 1024 }

    // MARK: - Initialization

    public init(configuration: DTLSEngineConfiguration) throws(DTLSEngineError) {
        // A client needs the crypto seams to run the handshake.
        guard let prfContext = configuration.prfContext,
              let transcriptContext = configuration.transcriptContext,
              configuration.ecdheGenerate != nil, configuration.ecdheAgree != nil,
              configuration.sign != nil, configuration.signingScheme != nil,
              configuration.verifyPeerSignature != nil, configuration.randomBytes != nil,
              configuration.recordProtectorFactory != nil else {
            throw .invalidConfiguration(reason: "DTLS client requires crypto seams (PRF/transcript/ecdhe/sign/verify/random/record protection)")
        }
        try DTLSSRTPNegotiation.validate(configuration.srtpProtectionProfiles)
        self.configuration = configuration
        self.fsm = DTLSClientHandshake(
            prfContext: prfContext,
            transcriptContext: transcriptContext
        )
        self.keyExchangeHandle = nil
        self.keyExchangeGroup = nil
        self.clientRandom = nil
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

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { phase == .connected }

    /// Whether the connection has been closed.
    public var isClosed: Bool { phase == .closed }

    /// Current caller-driven retransmission token and delay.
    public var retransmissionState: DTLSEngineRetransmissionState {
        flights.retransmissionState
    }

    /// The validated peer's application identifier bytes (e.g. a libp2p PeerID), or
    /// `nil` when no validator ran or it established trust without an identifier.
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

    /// Builds the initial ClientHello and returns the datagram(s) to send.
    public mutating func startHandshake() throws(DTLSEngineError) -> [[UInt8]] {
        guard phase == .start else {
            throw .handshakeAlreadyStarted
        }
        phase = .handshaking

        guard let randomBytes = configuration.randomBytes else {
            throw .invalidConfiguration(reason: "no random seam")
        }
        let random = try randomBytes(32)
        self.clientRandom = random

        let clientHello = DTLSClientHello(
            random: random,
            cipherSuites: configuration.supportedCipherSuites,
            useSRTP: try DTLSSRTPNegotiation.clientOffer(configuration.srtpProtectionProfiles)
        )
        let body: [UInt8]
        do { body = try clientHello.encodeBytes() }
        catch { throw .from(wire: error) }

        let actions: [DTLSCoreAction]
        do {
            actions = try fsm.start(
                clientHelloBody: body,
                clientRandom: random,
                requiredSRTPProfiles: configuration.srtpProtectionProfiles
            )
        } catch {
            phase = .failed
            throw .from(core: error)
        }

        var output = DTLSEngineOutput()
        try applyActions(actions, into: &output)
        let datagrams = output.datagramsToSend
        if !output.generatedFlightRecords.isEmpty {
            flights.startFlight(DTLSFlightRecipe(datagrams: [output.generatedFlightRecords]))
        }
        return datagrams
    }

    // MARK: - send / close / handleTimeout

    /// Encrypts application data into a DTLS datagram to send. Throws if the
    /// handshake is not complete or the connection is closed.
    public mutating func send(_ application: Span<UInt8>) throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { throw .connectionClosed }
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase == .connected else { throw .handshakeNotComplete }
        return try record.encodeRecord(contentType: .applicationData, plaintext: application)
    }

    /// Emits a close_notify alert datagram (encrypted if keys are active).
    public mutating func close() throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { return [] }
        phase = .closed
        flights.stop()
        // RFC 5246 §7.2: close_notify (level warning = 1, description 0).
        let alertBytes: [UInt8] = [1, 0]
        return try record.encodeRecord(contentType: .alert, plaintext: alertBytes.span)
    }

    /// Handles one caller-driven timeout only when `generation` still owns the
    /// active flight timer. Retransmitted records receive fresh record sequence
    /// numbers while preserving handshake message bytes and epochs.
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
}
