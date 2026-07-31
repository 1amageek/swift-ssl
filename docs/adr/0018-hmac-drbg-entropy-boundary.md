# ADR 0018: HMAC-DRBG entropy boundary

## Status

Accepted for the Pure Swift cryptographic boundary.

## Context

Key generation and protocol handshakes need random bytes, but a portable Swift
library cannot silently select an operating-system provider or treat a failed
entropy read as deterministic input. The source of entropy and the deterministic
random-bit generator therefore have separate responsibilities.

## Decision

- `EntropySource` remains an injected capability that must fill the complete
  caller-owned span or throw a typed `EntropyError`.
- `HMACDRBG` implements the SP 800-90A HMAC-DRBG state update using HMAC-SHA-256.
- The 32-byte key and 32-byte value are held by one noncopyable `SecretBytes`
  owner. Generate and reseed write only to caller-provided output spans.
- Instantiate, reseed, and generate enforce bounded seed/request sizes and the
  reseed interval. Additional input is processed before and after generation,
  including the empty-input update required by the construction.
- Entropy health tests, fork detection, platform adapters, and process-wide
  singleton policy remain outside the deterministic DRBG type.

## Verification

Native tests cover independent deterministic instantiate/generate and
additional-input fixtures plus request-limit failure before output mutation.
The same deterministic route is exercised by the pinned WASI and Embedded WASI
target-validation executables. Entropy fault, reseed-state, sanitizer,
allocation, and release benchmark gates remain open.

## Consequences

The cryptographic layer is deterministic once entropy is supplied, which makes
it testable on every target and prevents hidden platform fallback. Applications
must provide a real entropy adapter before using the generator for production
key material.
