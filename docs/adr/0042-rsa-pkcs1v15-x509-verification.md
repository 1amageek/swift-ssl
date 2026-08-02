# ADR 0042: Keep RSA PKCS #1 v1.5 verification behind the X.509 boundary

- Status: Accepted
- Date: 2026-08-02

## Context

The modern profile excludes RSA key transport and RSA PKCS #1 v1.5 TLS
CertificateVerify signing. Deployed certificate ecosystems still require
verification of `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, and
`sha512WithRSAEncryption`. Treating this compatibility requirement as a
general RSA signing capability would expand the secret-key surface and blur
the policy boundary between certificate validation and TLS authentication.

RFC 8017 requires RSASSA-PKCS1-v1_5 verification to recover an encoded message
with the public operation and compare it with the complete canonical
`EMSA-PKCS1-v1_5` encoding. The SHA-2 `DigestInfo` encoding used inside the
signature contains an explicit ASN.1 `NULL` parameter. Certificate algorithm
identifiers are a separate interoperability boundary and may encode their
parameters as `NULL` or absent.

## Decision

- `SwiftSSLCrypto.RSAPKCS1v15` is verification-only and accepts a validated
  `RSAPublicKey`, a caller-supplied message digest, and a closed SHA-2 hash
  identifier.
- The verifier reuses the bounded 2,048 through 4,096-bit fixed-width
  Montgomery public operation owned by the RSA-PSS implementation. No public
  mutable big-number API is introduced.
- Verification requires the entire recovered message to equal
  `00 01 FF...FF 00 DigestInfo || digest`, with at least eight `FF` bytes and
  the exact SHA-256, SHA-384, or SHA-512 DER `DigestInfo` prefix.
- DigestInfo prefix bytes are compared directly. Verification does not create
  a prefix owner or intermediate byte array.
- Signature and digest length errors and a signature integer greater than or
  equal to the modulus remain typed `CryptoInputError` failures. A
  well-sized, canonical integer with a mismatching encoded message returns
  `false`.
- `SwiftSSLX509.X509Certificate` owns signature-OID selection, RSA SPKI
  decoding, algorithm-parameter policy, TBS hashing, and the mapping from a
  cryptographic mismatch to `X509CertificateError`.
- RSA PKCS #1 v1.5 signing, private-key construction, RSA key transport,
  SHA-1, and MD5 remain outside the modern profile.

## Consequences

Certificate compatibility does not create a TLS signer capability. The same
safe public API and implementation execute on Native, WASI, and Embedded WASM.
The recovered RSA block is necessarily an owned fixed-width value, while the
signature and message digest remain borrowed.

Independent OpenSSL fixtures cover all three supported SHA-2 variants. A raw
RSA fixture whose internal DigestInfo omits the ASN.1 `NULL` parameter proves
that permissive noncanonical encodings are rejected. Real self-signed X.509
fixtures cover all three signature OIDs, mutation failure, and key-algorithm
mismatch. Native, WASI, and Embedded WASM target validation executes both a
valid signature and a modified signature. AddressSanitizer and Undefined
Behavior Sanitizer each pass the complete 163-test Core/Crypto set. Thread
Sanitizer evidence is unavailable on the pinned toolchain because Swift
frontend assertion `emitTsanInoutAccess` stops compilation before tests run.

Broader external differential corpora, allocation measurement, a formal
benchmark, and security review remain completion gates.
