/// DTLS 1.2 CertificateRequest (RFC 5246 Section 7.4.4).
///
/// The message carries client certificate kinds, signature/hash pairs, and an
/// optional vector of distinguished names for acceptable certificate authorities.

import NetworkingCore
import TLSWireCore
import TLSWireCore

/// The decoded DTLS 1.2 CertificateRequest body.
public struct DTLSCertificateRequest: Sendable {
    public let certificateTypes: [DTLSClientCertificateType]
    public let signatureAlgorithms: [SignatureScheme]
    public let certificateAuthorities: [[UInt8]]

    public init(
        certificateTypes: [DTLSClientCertificateType],
        signatureAlgorithms: [SignatureScheme],
        certificateAuthorities: [[UInt8]] = []
    ) {
        self.certificateTypes = certificateTypes
        self.signatureAlgorithms = signatureAlgorithms
        self.certificateAuthorities = certificateAuthorities
    }

    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = TLSWireWriter()
        var certificateTypeBytes: [UInt8] = []
        certificateTypeBytes.reserveCapacity(certificateTypes.count)
        for certificateType in certificateTypes {
            certificateTypeBytes.append(certificateType.rawValue)
        }
        try writer.dWriteVector8(certificateTypeBytes)

        var schemes = TLSWireWriter()
        for scheme in signatureAlgorithms {
            schemes.writeUInt16(scheme.rawValue)
        }
        try writer.dWriteVector16(schemes.finishArray())

        var authorities = TLSWireWriter()
        for authority in certificateAuthorities {
            try authorities.dWriteVector16(authority)
        }
        try writer.dWriteVector16(authorities.finishArray())
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> DTLSCertificateRequest {
        var reader = TLSWireReader(data)
        let certificateTypeBytes = try reader.dReadVector8()
        let signatureAlgorithmBytes = try reader.dReadVector16()
        guard signatureAlgorithmBytes.count >= 2,
              signatureAlgorithmBytes.count.isMultiple(of: 2) else {
            throw .dtls(.invalidFormat("Invalid CertificateRequest signature algorithms"))
        }

        var signatureReader = TLSWireReader(signatureAlgorithmBytes)
        var signatureAlgorithms: [SignatureScheme] = []
        while !signatureReader.isAtEnd {
            let rawValue = try signatureReader.dReadUInt16()
            if let scheme = SignatureScheme(rawValue: rawValue) {
                signatureAlgorithms.append(scheme)
            }
        }

        let authorityBytes = try reader.dReadVector16()
        guard reader.isAtEnd else {
            throw .dtls(.invalidFormat("CertificateRequest contains trailing bytes"))
        }
        var authorityReader = TLSWireReader(authorityBytes)
        var certificateAuthorities: [[UInt8]] = []
        while !authorityReader.isAtEnd {
            certificateAuthorities.append(try authorityReader.dReadVector16())
        }

        var certificateTypes: [DTLSClientCertificateType] = []
        certificateTypes.reserveCapacity(certificateTypeBytes.count)
        for rawValue in certificateTypeBytes {
            if let certificateType = DTLSClientCertificateType(rawValue: rawValue) {
                certificateTypes.append(certificateType)
            }
        }

        return DTLSCertificateRequest(
            certificateTypes: certificateTypes,
            signatureAlgorithms: signatureAlgorithms,
            certificateAuthorities: certificateAuthorities
        )
    }
}
