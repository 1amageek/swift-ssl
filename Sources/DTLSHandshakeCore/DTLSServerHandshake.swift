/// Embedded-clean DTLS 1.2 server handshake FSM (RFC 6347 / RFC 5246).
///
/// The server-side analogue of ``DTLSClientHandshake``: a single value-type,
/// sans-IO, caller-locked finite state machine spanning ClientHello (incl. the
/// HelloVerifyRequest cookie exchange) through the client Finished. It performs
/// **no I/O**, holds **no lock**, and never reaches for a clock —
/// `DTLSServerEngine` owns framing and drives this state machine, while `swift-tls`
/// owns the `Mutex` and supplies cookie HMAC, X.509-bound signature operations,
/// ECDHE agreement, and handshake randomness.
///
/// ## State
/// ```
/// idle → (HVR) → waitingClientHelloWithCookie → waitingClientKeyExchange
///      → waitingChangeCipherSpec → waitingFinished → connected
/// ```
///
/// ## Security invariants (preserved byte-for-byte)
/// - **Cookie binding (RFC 6347 §4.2.1) is fail-closed.** An empty cookie always
///   yields a HelloVerifyRequest; a non-empty cookie MUST validate (the adapter's
///   HMAC check is fed in) — a presented-but-unverifiable cookie is always rejected,
///   never silently accepted.
/// - **Client CertificateVerify proof-of-possession is verified by the adapter
///   (X.509) and folded fail-closed.** The CertificateVerify is recorded in the
///   transcript only after a successful verification, so the Finished hash covers it.
/// - **Client Finished MAC is verified** constant-time, fail-closed, after the
///   client-certificate policy is enforced (`requireClientCertificate` and the
///   "presented ⇒ must be verified" rule).
/// - **message_seq ordering / dedup** is owned here; a retransmit can never corrupt
///   the transcript.
///
/// Crypto operations are supplied through the concrete PRF and transcript
/// contexts. Embedded-clean: no Foundation, no `any`, no Mutex, no
/// ContinuousClock, no concrete crypto, no X.509, typed throws, no key paths.

import NetworkingCore
import TLSWireCore
import DTLSWireCore

/// The DTLS 1.2 server handshake FSM over the crypto seam.
public struct DTLSServerHandshake: Sendable {

    // MARK: - State

    /// Server handshake state (mirrors the legacy `DTLSServerState`).
    public enum ServerState: Sendable, Equatable {
        case idle
        case waitingClientHelloWithCookie
        case waitingClientKeyExchange
        case waitingChangeCipherSpec
        case waitingFinished
        case connected
    }

    // MARK: - Configuration

    /// When `true`, the handshake fails unless the client presents a certificate AND
    /// proves possession of its private key via a valid CertificateVerify.
    public let requireClientCertificate: Bool

    // MARK: - Stored Fields

    private let prfContext: DTLSPRFContext
    private let transcriptContext: DTLSTranscriptContext
    private var state: ServerState
    private var cipherSuite: DTLSCipherSuite?
    private var keySchedule: DTLSKeyScheduleCore?

    private var clientRandom: [UInt8]?
    private var serverRandom: [UInt8]?
    private var selectedSRTPProfile: SRTPProtectionProfile?

    /// Client's certificate DER (set on Certificate; surfaced to the adapter).
    public private(set) var clientCertificateDER: [UInt8]?
    /// Whether the client's CertificateVerify proof-of-possession has been verified.
    public private(set) var clientCertificateVerified: Bool

    private var messageSeq: UInt16
    public private(set) var nextReceiveSeq: UInt16

    private var handshakeMessages: [UInt8]
    /// The stateless-cookie response is retained only as handshake plaintext so a
    /// retransmitted initial ClientHello can receive the same HVR message_seq. It is
    /// never armed as a timed flight by the engine.
    private var helloVerifyRequestMessage: [UInt8]?

    // MARK: - Initialization

    public init(
        requireClientCertificate: Bool = false,
        prfContext: DTLSPRFContext,
        transcriptContext: DTLSTranscriptContext
    ) {
        self.requireClientCertificate = requireClientCertificate
        self.prfContext = prfContext
        self.transcriptContext = transcriptContext
        self.state = .idle
        self.cipherSuite = nil
        self.keySchedule = nil
        self.clientRandom = nil
        self.serverRandom = nil
        self.selectedSRTPProfile = nil
        self.clientCertificateDER = nil
        self.clientCertificateVerified = false
        self.messageSeq = 0
        self.nextReceiveSeq = 0
        self.handshakeMessages = []
        self.helloVerifyRequestMessage = nil
    }

    // MARK: - Accessors

    public var currentState: ServerState { state }
    public var isComplete: Bool { state == .connected }
    public var negotiatedCipherSuite: DTLSCipherSuite? { cipherSuite }
    public var nextExpectedReceiveSeq: UInt16 { nextReceiveSeq }

    /// The authenticated SRTP profile selected in ServerHello.
    public var negotiatedSRTPProfile: SRTPProtectionProfile? { selectedSRTPProfile }

    private mutating func nextMessageSeq() -> UInt16 {
        let seq = messageSeq
        messageSeq &+= 1
        return seq
    }

    // MARK: - ClientHello

    /// The outcome of decoding a ClientHello: either the server must reply with a
    /// HelloVerifyRequest (no cookie), or it must validate the presented cookie
    /// (fail-closed) before proceeding to the server flight.
    public enum ClientHelloOutcome: Sendable {
        /// No cookie: the adapter mints a HelloVerifyRequest cookie bound to this
        /// ClientHello and calls ``emitHelloVerifyRequest``.
        case needCookie(DTLSClientHello)
        /// A cookie was presented: the adapter verifies it (HMAC, fail-closed) and
        /// then calls ``serverFlight(acceptingCookieFrom:rawMessage:cookieValid:selectedSuite:inputs:)``.
        case verifyCookie(DTLSClientHello)
    }

    /// Decodes a received ClientHello and decides the cookie path. Does NOT touch
    /// the transcript yet (the cookie ClientHello is recorded only once accepted).
    public mutating func ingestClientHello(
        header: DTLSHandshakeHeader,
        body: [UInt8]
    ) throws(DTLSError) -> ClientHelloOutcome {
        guard header.messageType == .clientHello else {
            throw DTLSError.unexpectedMessage(expected: .clientHello, received: header.messageType)
        }
        let clientHello = try decodeClientHello(body)
        guard clientHello.extendedMasterSecret, clientHello.renegotiationInfo else {
            throw DTLSError.handshakeFailed("DTLS WebRTC profile requires EMS and secure renegotiation")
        }

        switch state {
        case .idle:
            guard header.messageSeq == nextReceiveSeq else {
                throw DTLSError.outOfOrderMessage(
                    expected: nextReceiveSeq,
                    received: header.messageSeq
                )
            }
            nextReceiveSeq = header.messageSeq &+ 1

        case .waitingClientHelloWithCookie:
            if header.messageSeq < nextReceiveSeq {
                // A retransmitted initial ClientHello means that the peer did not
                // receive our stateless HelloVerifyRequest. Returning `needCookie`
                // makes the adapter resend the retained response without changing
                // either sequence space.
                guard header.messageSeq == 0, clientHello.cookie.isEmpty else {
                    throw DTLSError.outOfOrderMessage(
                        expected: nextReceiveSeq,
                        received: header.messageSeq
                    )
                }
                return .needCookie(clientHello)
            }
            guard header.messageSeq == nextReceiveSeq else {
                throw DTLSError.outOfOrderMessage(
                    expected: nextReceiveSeq,
                    received: header.messageSeq
                )
            }
            if !clientHello.cookie.isEmpty {
                nextReceiveSeq = header.messageSeq &+ 1
            }

        case .waitingClientKeyExchange,
             .waitingChangeCipherSpec,
             .waitingFinished,
             .connected:
            throw DTLSError.invalidState("ClientHello received after cookie negotiation")
        }
        if clientHello.cookie.isEmpty {
            return .needCookie(clientHello)
        }
        return .verifyCookie(clientHello)
    }

    /// Emits the HelloVerifyRequest with the adapter-minted cookie body and waits for
    /// the cookie-carrying ClientHello.
    public mutating func emitHelloVerifyRequest(
        helloVerifyRequestBody: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        if state == .waitingClientHelloWithCookie,
           let helloVerifyRequestMessage {
            return [.sendMessage(helloVerifyRequestMessage)]
        }
        guard state == .idle else {
            throw DTLSError.invalidState("HelloVerifyRequest out of order")
        }
        let msg = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .helloVerifyRequest,
            messageSeq: nextMessageSeq(),
            body: helloVerifyRequestBody
        )
        helloVerifyRequestMessage = msg
        state = .waitingClientHelloWithCookie
        return [.sendMessage(msg)]
    }

    /// The crypto inputs the adapter computed for the server flight.
    public struct ServerFlightInputs: Sendable {
        /// The 32-byte ServerHello random (CSPRNG).
        public let serverRandom: [UInt8]
        /// The encoded server Certificate message body.
        public let certificateBody: [UInt8]
        /// The encoded ServerKeyExchange message body (already signed by the adapter).
        public let serverKeyExchangeBody: [UInt8]

        public init(serverRandom: [UInt8], certificateBody: [UInt8], serverKeyExchangeBody: [UInt8]) {
            self.serverRandom = serverRandom
            self.certificateBody = certificateBody
            self.serverKeyExchangeBody = serverKeyExchangeBody
        }
    }

    /// After the adapter validates a presented cookie (fail-closed; `cookieValid ==
    /// false` rejects), selects the cipher suite, and builds the signed server
    /// flight inputs, this records the cookie ClientHello, builds the server flight
    /// (ServerHello, Certificate, ServerKeyExchange, ServerHelloDone), and waits for
    /// the client's ClientKeyExchange.
    ///
    /// - Parameters:
    ///   - clientHello: the cookie-carrying ClientHello.
    ///   - rawMessage: the raw ClientHello message bytes (header + body) for the
    ///     transcript.
    ///   - cookieValid: the adapter's HMAC cookie-validation result. `false` rejects.
    ///   - selectedSuite: the negotiated cipher suite (adapter-resolved).
    ///   - inputs: the adapter-signed flight inputs.
    public mutating func serverFlight(
        acceptingCookieFrom clientHello: DTLSClientHello,
        rawMessage: [UInt8],
        cookieValid: Bool,
        selectedSuite: DTLSCipherSuite,
        inputs: ServerFlightInputs,
        selectedSRTP: DTLSUseSRTP? = nil
    ) throws(DTLSError) -> [DTLSCoreAction] {
        // A presented cookie MUST validate (RFC 6347 §4.2.1, fail-closed).
        guard cookieValid else {
            throw DTLSError.cookieMismatch
        }

        if let selectedSRTP {
            guard selectedSRTP.protectionProfiles.count == 1,
                  let profile = selectedSRTP.protectionProfiles.first,
                  clientHello.useSRTP?.protectionProfiles.contains(profile) == true,
                  selectedSRTP.mki.isEmpty else {
                throw DTLSError.handshakeFailed("Invalid SRTP server selection")
            }
            selectedSRTPProfile = profile
        } else {
            selectedSRTPProfile = nil
        }

        clientRandom = clientHello.random
        cipherSuite = selectedSuite
        keySchedule = DTLSKeyScheduleCore(
            cipherSuite: selectedSuite,
            prfContext: prfContext
        )
        serverRandom = inputs.serverRandom

        // Reset and record the cookie ClientHello (peer's raw bytes).
        handshakeMessages = []
        handshakeMessages.append(contentsOf: rawMessage)
        helloVerifyRequestMessage = nil

        // `ingestClientHello` advanced the peer sequence after accepting the
        // cookie-bearing ClientHello. RFC 6347 keeps message_seq monotonic across
        // the stateless cookie exchange even though the transcript is reset.

        var actions: [DTLSCoreAction] = []

        // ServerHello (adapter supplied the random; the body is built here so the
        // transcript records exactly the bytes sent).
        let serverHello = DTLSServerHello(
            random: inputs.serverRandom,
            cipherSuite: selectedSuite,
            useSRTP: selectedSRTP,
            extendedMasterSecret: true,
            renegotiationInfo: true
        )
        let shBody = encodeBytesOrTrap(serverHello)
        let shEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .serverHello,
            messageSeq: nextMessageSeq(),
            body: shBody
        )
        handshakeMessages.append(contentsOf: shEncoded)
        actions.append(.sendMessage(shEncoded))

        // Certificate (adapter-encoded body).
        let certEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .certificate,
            messageSeq: nextMessageSeq(),
            body: inputs.certificateBody
        )
        handshakeMessages.append(contentsOf: certEncoded)
        actions.append(.sendMessage(certEncoded))

        // ServerKeyExchange (adapter-signed body).
        let skeEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .serverKeyExchange,
            messageSeq: nextMessageSeq(),
            body: inputs.serverKeyExchangeBody
        )
        handshakeMessages.append(contentsOf: skeEncoded)
        actions.append(.sendMessage(skeEncoded))

        if requireClientCertificate {
            let request = DTLSCertificateRequest(
                certificateTypes: [.ecdsaSign],
                signatureAlgorithms: [.ecdsa_secp256r1_sha256]
            )
            let requestBody = encodeBytesOrTrap(request)
            let requestEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
                type: .certificateRequest,
                messageSeq: nextMessageSeq(),
                body: requestBody
            )
            handshakeMessages.append(contentsOf: requestEncoded)
            actions.append(.sendMessage(requestEncoded))
        }

        // ServerHelloDone.
        let shd = ServerHelloDone()
        let shdBody = encodeBytesOrTrap(shd)
        let shdEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .serverHelloDone,
            messageSeq: nextMessageSeq(),
            body: shdBody
        )
        handshakeMessages.append(contentsOf: shdEncoded)
        actions.append(.sendMessage(shdEncoded))

        state = .waitingClientKeyExchange
        return actions
    }

    // MARK: - Receive gate

    private enum ReceiveSeqClass {
        case duplicate
        case inOrder
    }

    private func classifyReceiveSeq(_ received: UInt16) throws(DTLSError) -> ReceiveSeqClass {
        if received == nextReceiveSeq { return .inOrder }
        if received < nextReceiveSeq { return .duplicate }
        throw DTLSError.outOfOrderMessage(expected: nextReceiveSeq, received: received)
    }

    // MARK: - Ingest dispatch (post-flight client messages)

    /// What the adapter must do after the core processes a received handshake message.
    public enum IngestResult: Sendable {
        /// Nothing further required; emit these actions.
        case actions([DTLSCoreAction])
        /// A client CertificateVerify arrived: the adapter must verify its signature
        /// against the presented certificate (X.509) over `transcript`, then call
        /// ``acceptClientCertificateVerify``.
        case verifyCertificateVerify(transcript: [UInt8], rawMessage: [UInt8])
        /// A client ClientKeyExchange arrived: the adapter must run ECDHE against
        /// `clientPublicKey` and call ``acceptClientKeyExchange``.
        case computeSharedSecret(clientPublicKey: [UInt8])
    }

    /// Begins processing a received handshake message (Certificate, CKE,
    /// CertificateVerify, Finished): runs the ordering gate + transcript append, then
    /// returns what the adapter must do next.
    public mutating func ingest(
        header: DTLSHandshakeHeader,
        body: [UInt8],
        rawMessage: [UInt8]
    ) throws(DTLSError) -> IngestResult {
        switch try classifyReceiveSeq(header.messageSeq) {
        case .duplicate:
            return .actions([])
        case .inOrder:
            nextReceiveSeq = header.messageSeq &+ 1
        }

        // Record in the transcript, except Finished (verify_data covers everything
        // before it) and CertificateVerify (recorded only after verification).
        if header.messageType != .finished && header.messageType != .certificateVerify {
            handshakeMessages.append(contentsOf: rawMessage)
        }

        switch (state, header.messageType) {
        case (.waitingClientKeyExchange, .certificate):
            let cert = try decodeCertificate(body)
            clientCertificateDER = cert.certificates.first
            return .actions([])

        case (.waitingClientKeyExchange, .clientKeyExchange):
            let cke = try decodeClientKeyExchange(body)
            return .computeSharedSecret(clientPublicKey: cke.publicKey)

        case (.waitingClientKeyExchange, .certificateVerify),
             (.waitingChangeCipherSpec, .certificateVerify):
            // The signature covers the transcript up to (not including) this message.
            guard clientCertificateDER != nil else {
                // CertificateVerify without a preceding Certificate is a protocol
                // violation — no key to verify possession against.
                throw DTLSError.unexpectedMessage(expected: .certificate, received: .certificateVerify)
            }
            return .verifyCertificateVerify(
                transcript: handshakeMessages,
                rawMessage: rawMessage
            )

        case (.waitingFinished, .finished):
            return try handleClientFinished(body, rawMessage: rawMessage)

        default:
            throw DTLSError.unexpectedMessage(
                expected: .clientKeyExchange,
                received: header.messageType
            )
        }
    }

    // MARK: - ClientKeyExchange

    /// Folds the adapter-computed ECDHE shared secret: derives the master secret +
    /// key block and emits `keysAvailable` + `expectChangeCipherSpec`.
    public mutating func acceptClientKeyExchange(
        sharedSecret: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        guard state == .waitingClientKeyExchange else {
            throw DTLSError.invalidState("ClientKeyExchange accepted out of order")
        }
        guard let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }
        // `ingest` recorded ClientKeyExchange before requesting the ECDHE shared
        // secret, so this is the exact RFC 7627 session_hash boundary.
        keySchedule?.configureExtendedMasterSecret(
            sessionHash: transcriptContext.hash(
                messages: handshakeMessages,
                cipherSuite: cipherSuite
            )
        )
        keySchedule?.deriveMasterSecret(
            preMasterSecret: sharedSecret,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )
        guard let ks = keySchedule else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        let keyBlock = try ks.deriveKeyBlock()
        guard let cipherSuite else {
            throw DTLSError.invalidState("Cipher suite not negotiated")
        }
        state = .waitingChangeCipherSpec
        return [.keysAvailable(keyBlock, cipherSuite), .expectChangeCipherSpec]
    }

    // MARK: - CertificateVerify

    /// Folds the adapter's CertificateVerify verification result (X.509, fail-closed).
    /// On success the CertificateVerify is recorded in the transcript so the Finished
    /// hash covers it.
    public mutating func acceptClientCertificateVerify(
        signatureValid: Bool,
        rawMessage: [UInt8]
    ) throws(DTLSError) {
        guard clientCertificateDER != nil else {
            throw DTLSError.unexpectedMessage(expected: .certificate, received: .certificateVerify)
        }
        guard signatureValid else {
            throw DTLSError.signatureVerificationFailed
        }
        clientCertificateVerified = true
        handshakeMessages.append(contentsOf: rawMessage)
    }

    // MARK: - ChangeCipherSpec

    public mutating func processChangeCipherSpec() throws(DTLSError) {
        guard state == .waitingChangeCipherSpec else {
            throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(state)")
        }
        state = .waitingFinished
    }

    // MARK: - Client Finished → server flight

    /// The decoded client Finished, parked until the policy + MAC checks run in
    /// ``handleClientFinished``.
    private mutating func handleClientFinished(
        _ body: [UInt8],
        rawMessage: [UInt8]
    ) throws(DTLSError) -> IngestResult {
        let finished = try decodeFinished(body)

        // Enforce the client-authentication policy BEFORE completing the handshake.
        if requireClientCertificate {
            guard clientCertificateDER != nil, clientCertificateVerified else {
                throw DTLSError.clientCertificateRequired
            }
        } else if clientCertificateDER != nil {
            guard clientCertificateVerified else {
                throw DTLSError.signatureVerificationFailed
            }
        }

        guard let ks = keySchedule else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        // Verify the client Finished (hash computed BEFORE adding to the transcript).
        let handshakeHash = transcriptContext.hash(messages: handshakeMessages, cipherSuite: cipherSuite)
        let expected = try ks.computeVerifyData(label: DTLSFinished.clientLabel, handshakeHash: handshakeHash)
        guard constantTimeEqual(finished.verifyData, expected) else {
            throw DTLSError.verifyDataMismatch
        }

        // Record the client Finished (peer's raw bytes) AFTER successful verification.
        handshakeMessages.append(contentsOf: rawMessage)

        // Build the server CCS + Finished + complete.
        var actions: [DTLSCoreAction] = []
        actions.append(.sendChangeCipherSpec)

        let serverHash = transcriptContext.hash(messages: handshakeMessages, cipherSuite: cipherSuite)
        let verifyData = try ks.computeVerifyData(label: DTLSFinished.serverLabel, handshakeHash: serverHash)
        let serverFinished = DTLSFinished(verifyData: verifyData)
        let sfBody = encodeBytesOrTrap(serverFinished)
        let sfEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .finished,
            messageSeq: nextMessageSeq(),
            body: sfBody
        )
        actions.append(.sendMessage(sfEncoded))
        actions.append(.handshakeComplete)

        state = .connected
        return .actions(actions)
    }

    /// Exports keying material only after Finished authentication completed.
    public func exportKeyingMaterial(
        label: String,
        context: [UInt8]?,
        length: Int
    ) throws(DTLSError) -> [UInt8] {
        guard state == .connected, let keySchedule else {
            throw DTLSError.invalidState("Exporter requested before handshake completion")
        }
        return try keySchedule.exportKeyingMaterial(
            label: label,
            context: context,
            length: length
        )
    }
}
