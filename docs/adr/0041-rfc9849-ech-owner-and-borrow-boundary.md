# ADR 0041: RFC 9849 ECH owner and borrow boundary

- Status: Accepted
- Date: 2026-08-02

## Context

ECH combines configuration parsing, HPKE, two related ClientHello encodings,
padding, transcript substitution, acceptance confirmation, and authenticated
rejection. Treating it as a Boolean extension would lose the ownership and
state transitions that prevent origin-name disclosure, ciphertext reuse, and
incorrect transcript selection.

## Decision

`SwiftSSLTLS` owns RFC 9849 ECH protocol semantics. Configuration acquisition,
DNS SVCB/HTTPS processing, immutable key-set rotation, and retry-transport
establishment remain caller responsibilities.

```mermaid
flowchart LR
    Snapshot["Immutable config/key snapshot"] --> Select["Strict suite selection"]
    Inner["Owned ClientHelloInner"] --> Seal["Single-owner HPKE sealer"]
    Select --> Seal
    Seal --> Outer["One final ClientHelloOuter owner"]
    Outer --> Open["Single-owner HPKE opener"]
    Snapshot --> Open
    Open --> Decision{"HPKE result"}
    Decision -->|accepted| Origin["Inner transcript and origin authentication"]
    Decision -->|rejected| Public["Outer transcript, public-name authentication, retry list"]
```

The public configuration and server key set are immutable owners. The sealer
and opener are noncopyable state owners because HPKE sequence state must have
one mutation path. Parsers retain checked byte ranges for encapsulation,
ciphertext, and legacy session ID. The opener borrows those ranges directly
from caller storage. It owns only the zeroed authenticated ClientHelloOuter
body required as HPKE associated data.

The sealer validates all counts and ranges before consuming HPKE sequence
state, allocates the final ClientHelloOuter once, copies the authenticated body
once, and seals ciphertext directly into its final payload range. Its unsafe
mutable-span boundary is scoped to that allocation: the array is the sole
owner, initialized and writable bounds are exact, `UInt8` alignment is
sufficient, mutation is exclusive, and no pointer escapes the closure.

Only HPKE authentication failure maps to ECH payload-authentication failure.
Key, KDF, memory, and configuration failures retain their typed causes. A
failed trial opening may continue only to another matching immutable server
configuration; it never falls back to plaintext success.

The TLS core authenticates the origin name and uses the inner transcript after
acceptance. Authenticated rejection uses the outer transcript, authenticates
the public name, returns retry configurations, and prevents origin application
data on that connection. HelloRetryRequest continuation and second-ClientHello
confirmation are not yet callable and remain completion work rather than a
silent fallback.

## Verification

- Native config and ClientHello positive/negative tests cover strict parsing,
  selection, padding, accept/reject, invalid encapsulation, and error identity.
- Stream/Core/QUIC tests cover accepted ECH, authenticated rejection, and PSK
  resumption using the inner binder transcript.
- The production target-validation route executes on Native, WASI, and
  Embedded WASI with the pinned Swift 6.4 toolchain and matching SDKs.
- Focused AddressSanitizer execution covers AES-GCM, HPKE, ECH config, and ECH
  ClientHello paths.
- Bidirectional interoperability at pinned BoringSSL commit
  `ae49d2681a56ca7b8609f6039a770fda2a8eb550` reaches accepted origin-name
  handling in both directions.

Formal allocation/copy measurement, the `1.10x` performance gate,
HelloRetryRequest continuation, rotation-snapshot concurrency tests, fuzzing,
a second independent peer, and security review remain required before the ECH
responsibility is complete.
