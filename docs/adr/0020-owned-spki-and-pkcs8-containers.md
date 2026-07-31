# ADR 0020: Owned SPKI and PKCS #8 containers

## Status

Accepted. These are structural format boundaries; algorithm implementations and certificate policy remain separate.

## Decision

`SwiftSSLX509` parses `SubjectPublicKeyInfo` and unencrypted `PrivateKeyInfo` from a single owned DER buffer. Parsed objects retain checked `ByteRange` values into that owner and expose key material only through scoped borrows. The parser does not create `Data`, does not retain caller pointers, and does not dispatch to a platform keychain.

`AlgorithmIdentifier` is parsed by `SwiftSSLASN1` into a canonical OID and a typed parameter shape (`absent`, `NULL`, OID, or other). `SwiftSSLX509` maps known OIDs to explicit algorithms (X25519, Ed25519, RSA encryption, and named EC curves) and preserves unknown OIDs as an explicit `unknown` value. Unknown algorithms are not silently treated as a supported key.

PKCS #8 version is checked against the optional public-key field: version 0 has no public key field and version 1 has exactly one. The optional attributes field is accepted only with its context-specific constructed tag and cannot appear twice. The implicit public-key bit string is checked for unused-bit and trailing-bit canonicality.

## Verification

Native `SwiftSSLX509Tests` cover an X25519 SPKI key range, non-zero unused-bit rejection, a PKCS #8 X25519 private-key range, and version-one/public-key consistency. Consumers must add signature/key algorithm validation before the container rows are considered complete.
