# ADR 0048: Keep TLS 1.3 client authentication in the semantic core

## Status

Accepted for main- and post-handshake client authentication.

## Context

Stream TLS, DTLS, and QUIC carry the same TLS 1.3 CertificateRequest,
Certificate, CertificateVerify, and Finished semantics through different
transport adapters. Implementing client authentication independently in each
adapter would permit transcript, identity-lifetime, and failure behavior to
diverge. A server also needs to distinguish path validation from proof of
private-key possession and must not expose a merely parsed certificate as an
authenticated peer identity.

## Decision

`TLS13ClientHandshakeCore` and `TLS13ServerHandshakeCore` own every
client-authentication state transition and transcript update.

- `TLS13ClientIdentity` is a noncopyable client-owned certificate chain and
  signing capability. Construction validates the leaf certificate, validity
  interval, supported Ed25519 public key, and certificate/key correspondence.
- `TLS13ClientAuthenticationConfiguration` pairs the server's optional or
  required presence policy with an injected `TLS13ClientCertificateValidating`
  implementation.
- `RFC5280TLS13ClientCertificateValidator` composes bounded RFC 5280 client path
  policy and explicit revocation evidence without network, filesystem, or
  platform trust-store I/O.
- `TLS13ValidatedClientCertificate` represents path-validated material only.
  The server exposes it as `authenticatedClientIdentity` only after the client
  CertificateVerify and Finished both verify.
- An absent or signature-scheme-incompatible client identity emits an empty
  Certificate. Optional mode continues without an identity; required mode
  fails explicitly.

`TLS13ClientAuthenticationTiming` selects main-handshake, post-handshake, or
both. A post-handshake exchange clones the transcript through the original
client Finished, appends only its own non-empty CertificateRequest context and
response, and authenticates Finished with the current client application
traffic secret. Context reuse and concurrent exchanges fail explicitly. The
caller generates the context and owns its unpredictability requirement.

Stream and DTLS adapters route post-handshake messages at the application
epoch. QUIC routes main-handshake authentication only and exposes no
post-handshake-authentication operation because RFC 9001 allows only
NewSessionTicket after the handshake. Adapters do not make trust or
authentication decisions.

## Consequences

- All three transports have one authentication contract and one failure path.
- Certificate path validation, proof of private-key possession, and handshake
  confirmation remain distinct states.
- Client signing ownership is never copied and is retained across a main
  handshake that does not request it, allowing a later authenticated borrow.
- Trust anchors and revocation evidence remain caller-supplied policy.
- The current signing profile is Ed25519; unsupported leaf keys fail with a
  typed error rather than selecting a compatibility backend.

## Verification

- CertificateRequest and empty Certificate codec round trips;
- required-mode success and authenticated identity exposure after Finished;
- optional-mode success with an empty Certificate;
- required-mode empty-Certificate rejection;
- tampered client CertificateVerify rejection;
- independent post-handshake transcript and current-application-secret
  Finished verification;
- duplicate context and tampered Finished rejection;
- local and external credential/signature/trust paths;
- Stream and DTLS application-epoch adapter integration, plus QUIC's explicit
  absence of a PHA API; and
- production-path execution on Native, WASI, and Embedded WASI with the pinned
  Swift 6.4 toolchain and explicit Embedded Unicode table linkage.
