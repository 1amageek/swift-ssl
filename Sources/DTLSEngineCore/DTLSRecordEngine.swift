/// The Embedded-clean, value-type DTLS 1.2 record layer (RFC 6347 §4.1).
///
/// `DTLSRecordEngine` is the cored, caller-locked replacement for the host
/// `DTLSRecordLayer` (`Mutex` + swift-crypto `SymmetricKey`). It owns the per-epoch
/// 48-bit sequence numbers, the read/write epochs, the 64-bit anti-replay window,
/// and the per-direction ``DTLSRecordProtectionContext``. The record framing,
/// AAD, and explicit-nonce assembly are byte-identical to the legacy layer; a
/// provider strategy constructs the concrete AEAD once and injects the immutable
/// protection context through ``DTLSEngineConfiguration``.
///
/// Security invariants preserved verbatim:
/// - the 48-bit per-epoch sequence number MUST NOT wrap (`encode` throws on
///   exhaustion — never silently reuses a nonce),
/// - epoch-mismatch records are discarded (`.epochMismatch`),
/// - the anti-replay check / AEAD authentication / window update are one
///   transaction (RFC 6347 §4.1.2.6), with a bad MAC discarded
///   (`.authenticationFailed`, RFC 6347 §4.1.2.7),
/// - read/write epochs advance on each CCS boundary; the write sequence resets
///   to 0 and the read replay window resets on their respective key changes.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no swift-crypto. The
/// engine intentionally has no crypto-provider generic parameter: Swift 6.4
/// normal WASM cannot safely construct cross-module metadata for stored associated-
/// type AEAD payloads, while the non-generic context preserves the same provider
/// selection and typed-failure contract.

import P2PCoreBytes
import DTLSWireCore
import DTLSRecordCore

/// The reason a received record was discarded at the wire level (RFC 6347
/// §4.1.2.7). Mirrors the host `DiscardReason`, value type.
enum DTLSRecordDiscardReason: Sendable, Equatable {
    case replayed
    case tooOld
    case epochMismatch
    case authenticationFailed
    case malformed
}

/// The outcome of decoding one record from a datagram.
enum DTLSRecordDecodeOutcome: Sendable {
    /// A valid (decrypted, if encrypted) record; `consumed` is the byte count.
    case record(contentType: DTLSContentType, fragment: [UInt8], consumed: Int)
    /// Not enough bytes for a complete record — stop the datagram loop.
    case insufficientData
    /// The record was discarded; `consumed` is the byte count (loop continues).
    case discarded(consumed: Int, reason: DTLSRecordDiscardReason)
}

struct DTLSRecordEngine: Sendable {

    // MARK: - Constants (RFC 6347 / RFC 5288)

    static var headerSize: Int { 13 }
    static var explicitNonceSize: Int { 8 }
    static var aeadTagSize: Int { 16 }
    static var aeadOverhead: Int { explicitNonceSize + aeadTagSize } // 24
    static var maxPlaintextSize: Int { 16384 }
    static var maxSequenceNumber: UInt64 { (1 << 48) - 1 }

    // MARK: - Epoch / sequence / keys (value-type, caller-locked)

    private struct WriteEpochState: Sendable {
        let epoch: UInt16
        var nextSequenceNumber: UInt64
        let protector: DTLSRecordProtectionContext?
    }

    private var readEpoch: UInt16 = 0

    /// The active write epoch plus the immediately preceding epoch. A retained
    /// DTLS flight can straddle one CCS boundary, so retransmission needs exactly
    /// these two key/sequence owners. Advancing again drops the now-obsolete epoch
    /// instead of growing an unbounded key history.
    private var currentWriteState = WriteEpochState(
        epoch: 0,
        nextSequenceNumber: 0,
        protector: nil
    )
    private var previousWriteState: WriteEpochState?

    private var readProtector: DTLSRecordProtectionContext?
    private var replayWindow = AntiReplayWindow()

    init() {}

    // MARK: - Key installation (CCS boundaries)

    /// Installs write keys and advances the write epoch, resetting the write seq.
    /// The prior epoch remains available for the one retained retransmission
    /// flight that can straddle this CCS boundary.
    mutating func setWriteKeys(
        protector: DTLSRecordProtectionContext
    ) throws(DTLSEngineError) {
        guard currentWriteState.epoch < UInt16.max else {
            throw .protocolFailure(reason: "DTLS write epoch exhausted")
        }
        previousWriteState = currentWriteState
        currentWriteState = WriteEpochState(
            epoch: currentWriteState.epoch + 1,
            nextSequenceNumber: 0,
            protector: protector
        )
    }

    /// Installs read keys and advances the read epoch, resetting the anti-replay
    /// window (RFC 6347 §4.1.2.6).
    mutating func setReadKeys(
        protector: DTLSRecordProtectionContext
    ) throws(DTLSEngineError) {
        guard readEpoch < UInt16.max else {
            throw .protocolFailure(reason: "DTLS read epoch exhausted")
        }
        readEpoch += 1
        readProtector = protector
        replayWindow.reset()
    }

    // MARK: - Encode (encrypt at the current write epoch)

    /// Encodes (and, once keys are installed, encrypts) a record at the current
    /// write epoch, advancing the write sequence number. Throws on seq exhaustion.
    mutating func encodeRecord(
        contentType: DTLSContentType,
        plaintext: [UInt8]
    ) throws(DTLSEngineError) -> [UInt8] {
        try encodeRecord(
            contentType: contentType,
            plaintext: plaintext,
            epoch: currentWriteState.epoch
        )
    }

    /// Captures a plaintext record recipe at the current write epoch and encodes
    /// its initial wire representation.
    mutating func encodeFlightRecord(
        contentType: DTLSContentType,
        plaintext: [UInt8]
    ) throws(DTLSEngineError) -> (bytes: [UInt8], recipe: DTLSFlightRecord) {
        let epoch = currentWriteState.epoch
        let bytes = try encodeRecord(
            contentType: contentType,
            plaintext: plaintext,
            epoch: epoch
        )
        return (
            bytes,
            DTLSFlightRecord(
                contentType: contentType,
                plaintext: plaintext,
                epoch: epoch
            )
        )
    }

    /// Re-encodes a retained flight record at its original epoch with a fresh
    /// epoch-local sequence number and therefore a fresh AEAD explicit nonce.
    mutating func encodeFlightRecord(
        _ recipe: DTLSFlightRecord
    ) throws(DTLSEngineError) -> [UInt8] {
        try encodeRecord(
            contentType: recipe.contentType,
            plaintext: recipe.plaintext,
            epoch: recipe.epoch
        )
    }

    var currentWriteEpoch: UInt16 { currentWriteState.epoch }

    private mutating func encodeRecord(
        contentType: DTLSContentType,
        plaintext: [UInt8],
        epoch: UInt16
    ) throws(DTLSEngineError) -> [UInt8] {
        guard plaintext.count <= Self.maxPlaintextSize else {
            throw .bufferOverflow
        }
        guard epoch <= currentWriteState.epoch else {
            throw .internalError(reason: "DTLS flight references a future write epoch")
        }
        let protector: DTLSRecordProtectionContext?
        if epoch == currentWriteState.epoch {
            protector = currentWriteState.protector
        } else if let previousWriteState, epoch == previousWriteState.epoch {
            protector = previousWriteState.protector
        } else {
            throw .internalError(reason: "DTLS write keys are unavailable for retained epoch \(epoch)")
        }
        guard epoch == 0 || protector != nil else {
            throw .internalError(reason: "DTLS protected write epoch has no key owner")
        }
        let seqNum = try allocateWriteSequenceNumber(for: epoch)
        var fragment = plaintext
        if epoch > 0, let protector {
            let explicitNonce = Self.buildExplicitNonce(epoch: epoch, sequenceNumber: seqNum)
            let aad = Self.buildAAD(
                epoch: epoch,
                sequenceNumber: seqNum,
                contentType: contentType,
                plaintextLength: plaintext.count
            )
            do {
                fragment = try protector.seal(plaintext: plaintext, explicitNonce: explicitNonce, aad: aad)
            } catch {
                throw .internalError(reason: "DTLS record seal failed: \(error)")
            }
        }
        return Self.encodeRecordBytes(
            contentType: contentType,
            epoch: epoch,
            sequenceNumber: seqNum,
            fragment: fragment
        )
    }

    private mutating func allocateWriteSequenceNumber(
        for epoch: UInt16
    ) throws(DTLSEngineError) -> UInt64 {
        if epoch == currentWriteState.epoch {
            let next = currentWriteState.nextSequenceNumber
            guard next <= Self.maxSequenceNumber else {
                throw .protocolFailure(reason: "DTLS write sequence number exhausted")
            }
            currentWriteState.nextSequenceNumber = next + 1
            return next
        }
        if var previous = previousWriteState, epoch == previous.epoch {
            let next = previous.nextSequenceNumber
            guard next <= Self.maxSequenceNumber else {
                throw .protocolFailure(reason: "DTLS write sequence number exhausted")
            }
            previous.nextSequenceNumber = next + 1
            previousWriteState = previous
            return next
        }
        throw .internalError(reason: "DTLS write sequence state is unavailable for epoch \(epoch)")
    }

    // MARK: - Decode (decrypt, replay-check)

    /// Decodes the first record at `offset` in `data`. Epoch-mismatch, replay,
    /// too-old, malformed, and bad-MAC records are discarded (loop continues); a
    /// valid record yields its content type + plaintext fragment.
    mutating func decodeRecord(
        from data: [UInt8],
        at offset: Int
    ) throws(DTLSEngineError) -> DTLSRecordDecodeOutcome {
        let available = data.count - offset
        guard available >= Self.headerSize else { return .insufficientData }

        var reader = ByteReader(data)
        try reader.eSkip(offset)
        let contentTypeRaw = try reader.eReadUInt8()
        guard let contentType = DTLSContentType(rawValue: contentTypeRaw) else {
            // An unknown content type in the header is a malformed datagram.
            throw .protocolFailure(reason: "unknown DTLS content type \(contentTypeRaw)")
        }
        _ = try reader.eReadUInt16() // version
        let epoch = try reader.eReadUInt16()
        let seqHigh = try reader.eReadUInt16()
        let seqLow = try reader.eReadUInt32()
        let sequenceNumber = UInt64(seqHigh) << 32 | UInt64(seqLow)
        let length = Int(try reader.eReadUInt16())

        let consumed = Self.headerSize + length
        guard available >= consumed else { return .insufficientData }
        let fragment = try reader.eReadBytes(length)

        // Epoch check (RFC 6347 §4.1): discard records from another epoch.
        if epoch != readEpoch {
            return .discarded(consumed: consumed, reason: .epochMismatch)
        }

        // Encrypted record (epoch > 0 with keys installed).
        if let protector = readProtector, epoch > 0 {
            guard fragment.count >= Self.aeadOverhead else {
                return .discarded(consumed: consumed, reason: .malformed)
            }
            let plaintextLength = fragment.count - Self.aeadOverhead
            guard plaintextLength <= Self.maxPlaintextSize else {
                return .discarded(consumed: consumed, reason: .malformed)
            }

            // Preliminary replay check (no state mutation yet).
            if replayWindow.isInitialized {
                let highest = replayWindow.currentHighest
                if sequenceNumber <= highest {
                    let diff = highest - sequenceNumber
                    if diff >= AntiReplayWindow.windowSize {
                        return .discarded(consumed: consumed, reason: .tooOld)
                    }
                    if replayWindow.isReceived(sequenceNumber: sequenceNumber) {
                        return .discarded(consumed: consumed, reason: .replayed)
                    }
                }
            }

            let aad = Self.buildAAD(
                epoch: epoch,
                sequenceNumber: sequenceNumber,
                contentType: contentType,
                plaintextLength: plaintextLength
            )
            let plaintext: [UInt8]
            do {
                plaintext = try protector.open(ciphertext: fragment, aad: aad)
            } catch {
                // Bad MAC / forged record: discard (RFC 6347 §4.1.2.7).
                return .discarded(consumed: consumed, reason: .authenticationFailed)
            }

            // Commit the window update only after authentication succeeds.
            guard replayWindow.shouldAccept(sequenceNumber: sequenceNumber) else {
                return .discarded(consumed: consumed, reason: .replayed)
            }
            return .record(contentType: contentType, fragment: plaintext, consumed: consumed)
        }

        // Unencrypted record (epoch 0): no replay protection.
        return .record(contentType: contentType, fragment: fragment, consumed: consumed)
    }

    // MARK: - Wire helpers (byte-identical to DTLSRecordCodec / DTLSRecordLayer)

    /// `explicit_nonce = epoch(2) || sequence_number(6)`.
    static func buildExplicitNonce(epoch: UInt16, sequenceNumber: UInt64) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        return writer.finishArray()
    }

    /// `AAD = epoch(2) || seq(6) || content_type(1) || version(2) || length(2)`.
    static func buildAAD(
        epoch: UInt16,
        sequenceNumber: UInt64,
        contentType: DTLSContentType,
        plaintextLength: Int
    ) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        writer.writeUInt8(contentType.rawValue)
        // ProtocolVersion DTLS 1.2 = 0xFEFD (major/minor on the wire).
        writer.writeUInt8(0xFE)
        writer.writeUInt8(0xFD)
        writer.writeUInt16(UInt16(plaintextLength & 0xFFFF))
        return writer.finishArray()
    }

    /// Encodes a full DTLS record (13-byte header + fragment).
    static func encodeRecordBytes(
        contentType: DTLSContentType,
        epoch: UInt16,
        sequenceNumber: UInt64,
        fragment: [UInt8]
    ) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeUInt8(contentType.rawValue)
        writer.writeUInt8(0xFE)
        writer.writeUInt8(0xFD)
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        writer.writeUInt16(UInt16(fragment.count & 0xFFFF))
        writer.writeBytes(fragment)
        return writer.finishArray()
    }
}
