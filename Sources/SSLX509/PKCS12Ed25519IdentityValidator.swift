import SSLCore
import SSLCrypto
import SSLASN1

enum PKCS12Ed25519IdentityValidator {
    static func validate(
        privateKey: borrowing PrivateKeyInfo,
        leafCertificate: borrowing CertificateBytes
    ) throws {
        guard privateKey.algorithm == .ed25519,
              privateKey.algorithmIdentifier.parameters == .absent else {
            throw PKCS12IdentityError.unsupportedPrivateKeyAlgorithm
        }

        let certificate: X509Certificate
        do {
            certificate = try X509Certificate(der: leafCertificate.span)
        } catch let error as X509CertificateError {
            throw PKCS12IdentityError.certificate(error)
        }
        guard certificate.subjectPublicKeyInfo.isEd25519 else {
            throw PKCS12IdentityError
                .unsupportedCertificatePublicKeyAlgorithm
        }

        let derivedPublicKey = try privateKey.withPrivateKeyBytes {
            privateKeyBytes throws -> ContiguousArray<UInt8> in
            var budget: ParsingBudget
            do {
                budget = try ParsingBudget(
                    limits: PrivateKeyInfo.defaultParsingLimits,
                    inputByteCount: privateKeyBytes.count
                )
            } catch let error as ResourceLimitError {
                throw PKCS12IdentityError.resourceLimit(error)
            }
            var cursor = DERCursor(privateKeyBytes)
            let seedElement: DERElementView
            do {
                seedElement = try cursor.readElement(using: &budget)
                try cursor.requireFullyConsumed()
            } catch let error as DERError {
                throw PKCS12IdentityError.der(error)
            }
            let octetStringTag = DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 4
            )
            guard seedElement.tag == octetStringTag,
                  seedElement.contentBytes.count
                    == Ed25519PrivateKey.seedByteCount else {
                throw PKCS12IdentityError.malformedEd25519PrivateKey
            }
            do {
                let key = try Ed25519PrivateKey(
                    seed: seedElement.contentBytes
                )
                return try key.publicKey()
            } catch let error as CryptoInputError {
                throw PKCS12IdentityError.cryptographicInput(error)
            }
        }

        let matches = certificate.subjectPublicKeyInfo.withPublicKeyBytes {
            certificatePublicKey in
            ConstantTime.equal(
                derivedPublicKey.span,
                certificatePublicKey
            )
        }
        guard matches else {
            throw PKCS12IdentityError.keyPairMismatch
        }
    }
}
