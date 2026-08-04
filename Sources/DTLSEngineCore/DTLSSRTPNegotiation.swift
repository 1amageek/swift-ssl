/// DTLS-SRTP configuration validation and server profile selection.

import DTLSWireCore

enum DTLSSRTPNegotiation {
    static func validate(
        _ profiles: [SRTPProtectionProfile]?
    ) throws(DTLSEngineError) {
        guard let profiles else { return }
        guard !profiles.isEmpty else {
            throw .invalidConfiguration(reason: "DTLS-SRTP profile list is empty")
        }
        for index in profiles.indices {
            guard !profiles[..<index].contains(profiles[index]) else {
                throw .invalidConfiguration(reason: "DTLS-SRTP profiles must be unique")
            }
        }
        guard profiles.allSatisfy({ $0 == .aes128CMHMACSHA180 }) else {
            throw .invalidConfiguration(
                reason: "Only SRTP_AES128_CM_HMAC_SHA1_80 is implemented"
            )
        }
    }

    static func clientOffer(
        _ profiles: [SRTPProtectionProfile]?
    ) throws(DTLSEngineError) -> DTLSUseSRTP? {
        guard let profiles else { return nil }
        do {
            return try DTLSUseSRTP(protectionProfiles: profiles)
        } catch {
            throw .invalidConfiguration(reason: "Invalid DTLS-SRTP client offer: \(error)")
        }
    }

    static func serverSelection(
        localProfiles: [SRTPProtectionProfile]?,
        clientOffer: DTLSUseSRTP?
    ) throws(DTLSEngineError) -> DTLSUseSRTP? {
        guard let localProfiles else { return nil }
        guard let clientOffer else {
            throw .protocolFailure(reason: "Client did not offer required SRTP")
        }
        guard let selected = localProfiles.first(where: clientOffer.protectionProfiles.contains) else {
            throw .protocolFailure(reason: "No mutually supported SRTP protection profile")
        }
        do {
            // This implementation does not own an MKI rotation context yet. RFC
            // 5764 permits the server to return an empty MKI when it cannot use the
            // client's offered MKI.
            return try DTLSUseSRTP(protectionProfiles: [selected])
        } catch {
            throw .internalError(reason: "Failed to encode validated SRTP selection: \(error)")
        }
    }
}
