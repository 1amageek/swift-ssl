# ADR 0023: X.509 structural owner boundary

## Status

Accepted. Structural parsing is deliberately separated from signature verification and RFC 5280 policy.

## Decision

`X509Certificate` owns one immutable DER buffer and stores checked ranges for the complete `TBSCertificate` and signature BIT STRING. It parses version, canonical positive serial bytes, the duplicated signature `AlgorithmIdentifier`, issuer/subject sequence boundaries, validity times, and `SubjectPublicKeyInfo`. It requires the outer and TBS signature algorithms to match and rejects malformed optional issuer/subject unique IDs and duplicate extensions.

Validity values are retained as strict ASCII UTCTime/GeneralizedTime strings with a `Z` suffix. This is a syntax boundary only; comparing times, checking certificate validity windows, and applying name constraints belong to the policy engine.

The parser does not verify signatures, interpret extension OIDs, build a path, consult a trust store, or fall back from SAN to Common Name. Those operations consume the structural object through explicit protocol boundaries.

## Verification

Native `SwiftSSLX509Tests` parse a deterministic v1 certificate fixture, verify certificate/TBS/signature ranges, compare duplicated signature algorithm identifiers, retain X25519 SPKI key ranges, and validate time syntax. Negative extension, signature, and policy tests are required as each consumer is added.
