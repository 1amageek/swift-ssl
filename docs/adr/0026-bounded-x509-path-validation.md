# ADR 0026: Bounded X.509 path validation

## Status

Accepted for the strict certificate-path layer. Revocation, advanced RFC 5280
policy, and trust-store acquisition remain separate responsibilities.

## Context

Parsing a certificate and verifying its own signature is not sufficient for
PKI. A TLS caller needs the issuer relationship, validity windows, CA
constraints, trust-anchor boundary, and SAN identity decision to be explicit.
The protocol layer must not perform an unbounded search or silently accept a
partial chain.

## Decision

`X509Certificate` retains immutable DER owners for the issuer and subject Name
elements and can verify its signature against an explicitly supplied issuer
SPKI. `X509PathValidator` performs a bounded breadth-first search over caller-
supplied intermediates and immutable trust anchors. Every edge requires:

- exact DER Name equality between child issuer and issuer subject;
- validity at the requested `VerificationInstant`;
- BasicConstraints `cA = TRUE` and path-length enforcement;
- `keyCertSign` when a KeyUsage extension is present; and
- the child signature to verify with the issuer key.

The trust anchor is an explicit caller-owned record. Optional hostname
validation is applied only to the leaf and uses the existing SAN-only matcher.
No network, filesystem, revocation fetch, or platform trust-store behavior is
implicit in this layer.

## Consequences

- A certificate can no longer be treated as trusted merely because its DER
  parses or its self-signature verifies.
- The search has a fixed path bound and reports typed failure for missing
  issuers, loops, invalid constraints, and signature failures.
- CRL/OCSP, name constraints, Certificate Transparency, and policy mapping
  still require dedicated validators before a complete RFC 5280 profile claim.
