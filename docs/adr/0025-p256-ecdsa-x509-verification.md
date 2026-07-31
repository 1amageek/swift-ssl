# ADR 0025: P-256 ECDSA verification in the X.509 path

## Status

Accepted for the validation path. Production release remains blocked by the
constant-time, differential, target, and performance gates recorded in the
responsibility matrix.

## Context

P-256 is a common certificate signing key even when a TLS profile negotiates
X25519 for key agreement. Supporting only Ed25519 certificate signatures left
the certificate verification path unable to consume a significant modern PKI
profile.

## Decision

`SwiftSSLCrypto.P256ECDSA` verifies fixed-width `r || s` signatures over a
caller-provided digest. `SwiftSSLX509.X509Certificate.verifySignature()` owns
the protocol-specific boundary: it accepts only the three ECDSA-with-SHA2
algorithm identifiers, requires absent algorithm parameters, requires a
prime256v1 SPKI, strictly decodes the DER sequence of two positive integers,
and truncates SHA-384/SHA-512 digests to the P-256 order width through the
crypto primitive.

The verifier is intentionally not selected by the TLS handshake engine yet.
The P-256 arithmetic is shared with the standalone ECDH primitive and still
requires a constant-time audit and independent differential corpus before it
can become a production authentication backend.

## Consequences

- Real P-256 ECDSA certificates can be parsed and signature-verified without a
  platform cryptography or BoringSSL dependency.
- Malformed DER integers, non-canonical encodings, out-of-range `r`/`s`, and
  modified signatures fail explicitly as signature verification failures.
- P-384/P-521, RSA-PSS, ECDSA signing, and TLS CertificateVerify integration
  remain separate implementation responsibilities.
- The validation-only marker remains on both the primitive and façade so a
  callable path cannot be mistaken for a completed security release.
