import SwiftSSLCore
import SwiftSSLCrypto

/// Verifies RFC 6962 v1 SCT signatures for X.509 and precertificate entries.
/// Log-list and inclusion-proof acquisition remain external capabilities.
public struct RFC6962CertificateTransparencyVerifier:
    CertificateTransparencyVerifying,
    Sendable
{
    public let policy: CertificateTransparencyPolicy

    public init(policy: CertificateTransparencyPolicy = .init()) {
        self.policy = policy
    }

    public func verify(
        certificate: borrowing X509Certificate,
        timestamps: borrowing SignedCertificateTimestampList,
        logs: borrowing ContiguousArray<CertificateTransparencyLog>,
        at instant: VerificationInstant
    ) throws(CertificateTransparencyError) {
        try Self.requireUniqueLogIdentifiers(logs)
        var acceptedLogIdentifiers = ContiguousArray<OwnedBytes>()
        var acceptedOperators = ContiguousArray<UInt64>()
        var index = 0
        while index < timestamps.timestamps.count {
            let timestamp = timestamps.timestamps[index]
            if !acceptedLogIdentifiers.contains(timestamp.logIdentifier),
               let logIndex = Self.findLogIndex(
                   timestamp.logIdentifier,
                   in: logs
               ),
               let timestampInstant = Self.instant(
                   milliseconds: timestamp.timestampMilliseconds
               ),
               timestampInstant <= Self.addingSeconds(
                   policy.maximumClockSkewSeconds,
                   to: instant
               ),
               certificate.validity.contains(timestampInstant),
               logs[logIndex].isQualified(at: timestampInstant),
               Self.hasSupportedAlgorithm(timestamp),
               Self.hasValidSignature(
                   timestamp,
                   certificate: certificate,
                   log: logs[logIndex]
               ) {
                acceptedLogIdentifiers.append(timestamp.logIdentifier)
                let operatorIdentifier = logs[logIndex].operatorIdentifier
                if !acceptedOperators.contains(operatorIdentifier) {
                    acceptedOperators.append(operatorIdentifier)
                }
            }
            index += 1
        }
        guard acceptedLogIdentifiers.count >= policy.minimumValidSCTCount else {
            throw .insufficientValidSCTs(
                required: policy.minimumValidSCTCount,
                actual: acceptedLogIdentifiers.count
            )
        }
        guard acceptedOperators.count >= policy.minimumDistinctOperatorCount else {
            throw .insufficientDistinctOperators(
                required: policy.minimumDistinctOperatorCount,
                actual: acceptedOperators.count
            )
        }
    }

    public func verify(
        precertificate: borrowing RFC6962Precertificate,
        logs: borrowing ContiguousArray<CertificateTransparencyLog>,
        at instant: VerificationInstant
    ) throws(CertificateTransparencyError) {
        try Self.requireUniqueLogIdentifiers(logs)
        var acceptedLogIdentifiers = ContiguousArray<OwnedBytes>()
        var acceptedOperators = ContiguousArray<UInt64>()
        var index = 0
        while index < precertificate.timestamps.timestamps.count {
            let timestamp = precertificate.timestamps.timestamps[index]
            if !acceptedLogIdentifiers.contains(timestamp.logIdentifier),
               let logIndex = Self.findLogIndex(
                   timestamp.logIdentifier,
                   in: logs
               ),
               let timestampInstant = Self.instant(
                   milliseconds: timestamp.timestampMilliseconds
               ),
               timestampInstant <= Self.addingSeconds(
                   policy.maximumClockSkewSeconds,
                   to: instant
               ),
               precertificate.validity.contains(timestampInstant),
               logs[logIndex].isQualified(at: timestampInstant),
               Self.hasSupportedAlgorithm(timestamp),
               Self.hasValidSignature(
                   timestamp,
                   precertificate: precertificate,
                   log: logs[logIndex]
               ) {
                acceptedLogIdentifiers.append(timestamp.logIdentifier)
                let operatorIdentifier = logs[logIndex].operatorIdentifier
                if !acceptedOperators.contains(operatorIdentifier) {
                    acceptedOperators.append(operatorIdentifier)
                }
            }
            index += 1
        }
        guard acceptedLogIdentifiers.count >= policy.minimumValidSCTCount else {
            throw .insufficientValidSCTs(
                required: policy.minimumValidSCTCount,
                actual: acceptedLogIdentifiers.count
            )
        }
        guard acceptedOperators.count >= policy.minimumDistinctOperatorCount else {
            throw .insufficientDistinctOperators(
                required: policy.minimumDistinctOperatorCount,
                actual: acceptedOperators.count
            )
        }
    }

    private static func hasValidSignature(
        _ timestamp: borrowing SignedCertificateTimestamp,
        certificate: borrowing X509Certificate,
        log: borrowing CertificateTransparencyLog
    ) -> Bool {
        do {
            let signedData = try makeSignedData(
                timestamp,
                certificate: certificate
            )
            let algorithm = try signatureAlgorithm(timestamp)
            try X509SignedPayloadVerifier.verify(
                signedBytes: signedData.span,
                signature: timestamp.signature.span,
                algorithm: algorithm,
                using: log.publicKey
            )
            return true
        } catch {
            return false
        }
    }

    private static func hasValidSignature(
        _ timestamp: borrowing SignedCertificateTimestamp,
        precertificate: borrowing RFC6962Precertificate,
        log: borrowing CertificateTransparencyLog
    ) -> Bool {
        do {
            let signedData = try makeSignedData(
                timestamp,
                precertificate: precertificate
            )
            let algorithm = try signatureAlgorithm(timestamp)
            try X509SignedPayloadVerifier.verify(
                signedBytes: signedData.span,
                signature: timestamp.signature.span,
                algorithm: algorithm,
                using: log.publicKey
            )
            return true
        } catch {
            return false
        }
    }

    private static func makeSignedData(
        _ timestamp: borrowing SignedCertificateTimestamp,
        certificate: borrowing X509Certificate
    ) throws(CertificateTransparencyError) -> OwnedBytes {
        try certificate.withDERBytes {
            certificateDER throws(CertificateTransparencyError) in
            guard certificateDER.count <= 0x00FF_FFFF,
                  timestamp.extensions.count <= Int(UInt16.max) else {
                throw .signedDataTooLarge
            }
            let byteCount = 1 + 1 + 8 + 2 + 3 + certificateDER.count
                + 2 + timestamp.extensions.count
            do {
                return try makeSignedDataBytes(
                    timestamp,
                    certificateDER: certificateDER,
                    byteCount: byteCount
                )
            } catch let error as ByteError {
                throw .byte(error)
            } catch {
                throw .signedDataTooLarge
            }
        }
    }

    private static func makeSignedDataBytes(
        _ timestamp: borrowing SignedCertificateTimestamp,
        certificateDER: Span<UInt8>,
        byteCount: Int
    ) throws(ByteError) -> OwnedBytes {
        var builder = try ByteBuilder(
            maximumByteCount: byteCount,
            minimumCapacity: byteCount
        )
        try builder.append(timestamp.version)
        try builder.append(0)
        try appendUInt64(timestamp.timestampMilliseconds, to: &builder)
        try builder.appendUInt16BigEndian(0)
        try builder.appendUInt24BigEndian(UInt32(certificateDER.count))
        try builder.append(certificateDER)
        try builder.appendUInt16BigEndian(UInt16(timestamp.extensions.count))
        try builder.append(timestamp.extensions.span)
        return builder.finish()
    }

    private static func makeSignedData(
        _ timestamp: borrowing SignedCertificateTimestamp,
        precertificate: borrowing RFC6962Precertificate
    ) throws(CertificateTransparencyError) -> OwnedBytes {
        try precertificate.withTBSCertificateBytes {
            tbsCertificate throws(CertificateTransparencyError) in
            guard precertificate.issuerKeyHash.count == SHA256.digestByteCount,
                  tbsCertificate.count <= 0x00FF_FFFF,
                  timestamp.extensions.count <= Int(UInt16.max) else {
                throw .signedDataTooLarge
            }
            let byteCount = 1 + 1 + 8 + 2 + SHA256.digestByteCount
                + 3 + tbsCertificate.count + 2 + timestamp.extensions.count
            do {
                var builder = try ByteBuilder(
                    maximumByteCount: byteCount,
                    minimumCapacity: byteCount
                )
                try builder.append(timestamp.version)
                try builder.append(0)
                try appendUInt64(timestamp.timestampMilliseconds, to: &builder)
                try builder.appendUInt16BigEndian(1)
                try builder.append(precertificate.issuerKeyHash.span)
                try builder.appendUInt24BigEndian(UInt32(tbsCertificate.count))
                try builder.append(tbsCertificate)
                try builder.appendUInt16BigEndian(
                    UInt16(timestamp.extensions.count)
                )
                try builder.append(timestamp.extensions.span)
                return builder.finish()
            } catch let error as ByteError {
                throw .byte(error)
            } catch {
                throw .signedDataTooLarge
            }
        }
    }

    private static func signatureAlgorithm(
        _ timestamp: borrowing SignedCertificateTimestamp
    ) throws(CertificateTransparencyError) -> X509SignatureAlgorithm {
        let encoded: ContiguousArray<UInt8>
        switch (timestamp.hashAlgorithm, timestamp.signatureAlgorithm) {
        case (4, 3):
            encoded = [
                0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
                0xCE, 0x3D, 0x04, 0x03, 0x02,
            ]
        case (4, 1):
            encoded = [
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
                0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
            ]
        default:
            throw .unsupportedSignatureAlgorithm(
                hash: timestamp.hashAlgorithm,
                signature: timestamp.signatureAlgorithm
            )
        }
        let owned = OwnedBytes(consuming: encoded)
        return try owned.withBorrowedBytes {
            bytes throws(CertificateTransparencyError) in
            do {
                return try X509SignatureAlgorithm(der: bytes)
            } catch let error as X509SignatureVerificationError {
                throw .signature(error)
            } catch {
                throw .invalidSCT
            }
        }
    }

    private static func hasSupportedAlgorithm(
        _ timestamp: borrowing SignedCertificateTimestamp
    ) -> Bool {
        (timestamp.hashAlgorithm == 4
            && timestamp.signatureAlgorithm == 3)
        || (timestamp.hashAlgorithm == 4
            && timestamp.signatureAlgorithm == 1)
    }

    private static func findLogIndex(
        _ identifier: borrowing OwnedBytes,
        in logs: borrowing ContiguousArray<CertificateTransparencyLog>
    ) -> Int? {
        var index = 0
        while index < logs.count {
            if identifiersEqual(identifier, logs[index].logIdentifier) {
                return index
            }
            index += 1
        }
        return nil
    }

    private static func requireUniqueLogIdentifiers(
        _ logs: borrowing ContiguousArray<CertificateTransparencyLog>
    ) throws(CertificateTransparencyError) {
        var left = 0
        while left < logs.count {
            var right = left + 1
            while right < logs.count {
                if identifiersEqual(
                    logs[left].logIdentifier,
                    logs[right].logIdentifier
                ) {
                    throw .duplicateLogIdentifier
                }
                right += 1
            }
            left += 1
        }
    }

    private static func identifiersEqual(
        _ left: borrowing OwnedBytes,
        _ right: borrowing OwnedBytes
    ) -> Bool {
        left.withBorrowedBytes { leftBytes in
            right.withBorrowedBytes { rightBytes in
                ConstantTime.equal(leftBytes, rightBytes)
            }
        }
    }

    private static func instant(
        milliseconds: UInt64
    ) -> VerificationInstant? {
        let seconds = milliseconds / 1_000
        guard seconds <= UInt64(Int64.max) else { return nil }
        let nanoseconds = UInt32((milliseconds % 1_000) * 1_000_000)
        do {
            return try VerificationInstant(
                secondsSinceUnixEpoch: Int64(seconds),
                nanoseconds: nanoseconds
            )
        } catch {
            return nil
        }
    }

    private static func addingSeconds(
        _ seconds: Int64,
        to instant: VerificationInstant
    ) -> VerificationInstant {
        let result = instant.secondsSinceUnixEpoch.addingReportingOverflow(
            seconds
        )
        let value = result.overflow ? Int64.max : result.partialValue
        do {
            return try VerificationInstant(
                secondsSinceUnixEpoch: value,
                nanoseconds: instant.nanoseconds
            )
        } catch {
            preconditionFailure("existing nanoseconds are always valid")
        }
    }

    private static func appendUInt64(
        _ value: UInt64,
        to builder: inout ByteBuilder
    ) throws(ByteError) {
        var shift = 56
        while shift >= 0 {
            try builder.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            shift -= 8
        }
    }
}
