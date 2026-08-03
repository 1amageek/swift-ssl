# ADR 0020: Owned SPKI and PKCS #8 containers

## Status

Accepted. These are structural format boundaries; algorithm implementations and certificate policy remain separate.

## Decision

`SSLX509` parses `SubjectPublicKeyInfo` from an immutable owned DER buffer
and unencrypted `PrivateKeyInfo` from a noncopyable, wiped `SecretBytes` DER
owner. Parsed objects retain checked `ByteRange` values into their owner and
expose material only through scoped borrows. The parser does not create `Data`,
does not retain caller pointers, and does not dispatch to a platform keychain.

For EC keys, the PKCS #8 private-key payload is parsed as RFC 5915
`ECPrivateKey`. Its version, explicit named-curve parameters, scalar-sized
encoding, optional implicit public-key bit string, field ordering, and
outer/inner curve agreement are checked before a crypto key owner can be
created. The scalar is copied into a dedicated `SecretBytes` owner; the source
PKCS #8 document also remains in wiped storage until its noncopyable owner is
destroyed.

`AlgorithmIdentifier` is parsed by `SSLASN1` into a canonical OID and a typed parameter shape (`absent`, `NULL`, OID, or other). `SSLX509` maps known OIDs to explicit algorithms (X25519, Ed25519, RSA encryption, and named EC curves) and preserves unknown OIDs as an explicit `unknown` value. Unknown algorithms are not silently treated as a supported key.

PKCS #8 version is checked against the optional public-key field: version 0 has no public key field and version 1 has exactly one. The optional attributes field is accepted only with its context-specific constructed tag and cannot appear twice. The implicit public-key bit string is checked for unused-bit and trailing-bit canonicality.

## Verification

Native `SSLX509Tests` cover an X25519 SPKI key range, non-zero unused-bit rejection, PKCS #8 X25519 private-key ranges, version-one/public-key consistency, RFC 5915 P-256 parsing, and curve-mismatch rejection. Under ADR 0036, RFC 5915 decoding remains a format and ownership responsibility only; there is no conversion from `ECPrivateKey` to `TLS13SigningKey`. Constant-time arithmetic and differential evidence remain separate crypto release gates for callable secret operations.
