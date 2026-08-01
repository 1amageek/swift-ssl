# ADR 0020: Owned SPKI and PKCS #8 containers

## Status

Accepted. These are structural format boundaries; algorithm implementations and certificate policy remain separate.

## Decision

`SwiftSSLX509` parses `SubjectPublicKeyInfo` and unencrypted `PrivateKeyInfo` from a single owned DER buffer. Parsed objects retain checked `ByteRange` values into that owner and expose key material only through scoped borrows. The parser does not create `Data`, does not retain caller pointers, and does not dispatch to a platform keychain.

For EC keys, the PKCS #8 private-key payload is parsed as RFC 5915 `ECPrivateKey`. Its version, explicit named-curve parameters, scalar-sized encoding, optional implicit public-key bit string, field ordering, and outer/inner curve agreement are checked before a crypto key owner can be created. The scalar is copied into a dedicated `SecretBytes` owner and is never retained in the DER container.

`AlgorithmIdentifier` is parsed by `SwiftSSLASN1` into a canonical OID and a typed parameter shape (`absent`, `NULL`, OID, or other). `SwiftSSLX509` maps known OIDs to explicit algorithms (X25519, Ed25519, RSA encryption, and named EC curves) and preserves unknown OIDs as an explicit `unknown` value. Unknown algorithms are not silently treated as a supported key.

PKCS #8 version is checked against the optional public-key field: version 0 has no public key field and version 1 has exactly one. The optional attributes field is accepted only with its context-specific constructed tag and cannot appear twice. The implicit public-key bit string is checked for unused-bit and trailing-bit canonicality.

## Verification

Native `SwiftSSLX509Tests` cover an X25519 SPKI key range, non-zero unused-bit rejection, PKCS #8 X25519 private-key ranges, version-one/public-key consistency, RFC 5915 P-256 parsing, and curve-mismatch rejection. `TLS13SigningKey.fromECPrivateKey` additionally validates the derived public point before selecting a TLS signer. Constant-time arithmetic and differential evidence remain separate crypto release gates.
