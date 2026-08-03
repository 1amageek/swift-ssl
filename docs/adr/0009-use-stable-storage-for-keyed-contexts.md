# ADR 0009: Use stable storage for keyed incremental contexts

- Status: Accepted
- Date: 2026-07-31

## Context

An incremental HMAC context must retain key-derived inner and outer SHA-256 state across calls, expose noncopyable ownership, and erase the original state before its storage is released. The pinned Swift 6.4 snapshot cannot safely mutate the original inline fields of a noncopyable value from its deinitializer. Moving those fields into local values during destruction only wipes the local copies after optimization.

A manually allocated `UnsafeMutablePointer` gives the state a stable address, but mutating a noncopyable pointee through `.pointee` triggers the pinned compiler's Thread Sanitizer SIL-generation assertion. Moving the same access into a helper does not change that boundary. Disabling TSan, weakening the context to a copyable owner, or selecting a target-specific implementation would violate the verification and cross-target ownership contracts.

## Decision

`HMACSHA256Context` remains the public noncopyable owner and contains one private reference to a final `HMACSHA256ContextStorage` object. The storage object owns the inner and outer SHA-256 contexts at stable addresses and is never exposed outside `SSLCrypto`.

The reference is logically unique because it is created only for the noncopyable context, remains private, does not cross a `Sendable` boundary, and is never returned or stored elsewhere. All state access is synchronous. ARC owns exactly-once destruction and deallocation.

`HMACSHA256ContextStorage.deinit` wipes both SHA-256 state words and both pending blocks in their original object storage before deallocation. Key normalization state, the padded key block, the inner digest, and calculated verification tags remain scoped stack values with explicit `defer`-based volatile erasure.

The source and ownership model are identical on Native, WASI, and Embedded WASI. Target differences are limited to the runtime's class deallocation implementation.

## Alternatives considered

| Alternative | Decision |
|---|---|
| Inline noncopyable SHA-256 fields | Rejected because the pinned snapshot cannot proveably wipe the original inline storage from `deinit` |
| Manual typed pointer storage | Rejected because TSan crashes during SIL generation for the required mutating pointee access |
| Conditional sanitizer or target fallback | Rejected because it weakens one semantic implementation and hides an unverified path |
| Copyable public context | Rejected because it permits unintended duplication of keyed state |

## Consequences

- An escaping incremental context performs one storage allocation at creation. Updates perform no allocation, reference-count operation, or HMAC-layer input copy.
- The concrete one-shot operation uses scoped inline prepared and working contexts with explicit cleanup; it does not construct the escaping storage owner.
- The class header increases the current Native storage size from 224 bytes of fields to a 240-byte object. Whole-module optimization may stack-promote a scoped one-shot operation.
- ARC, rather than handwritten allocation code, owns exactly-once deallocation.
- The storage class remains an internal implementation detail; the safe public API is the noncopyable context and scoped spans.
- Future keyed contexts should use this pattern only when optimized-code inspection proves original-storage erasure and the allocation budget is acceptable.

## Verification

The release gate inspects Native, WASI, and Embedded WASI LLVM IR at both `-O` and `-Osize`. It requires:

1. two 32-byte and two 64-byte volatile wipes whose pointers derive from the storage object's `self`;
2. no temporary `SHA256Context` copy in the destruction path;
3. the inline wipes, or a verified wipe helper call, before class deallocation;
4. cleanup of every keyed stack temporary on success and failure paths;
5. no allocation, retain, release, or HMAC-layer copy in the update method.

The same implementation passes the HMAC correctness suite under Address Sanitizer, Thread Sanitizer, and Undefined Behavior Sanitizer. Native, WASI, and Embedded WASI execute the façade-level RFC 4231 validation path with the pinned toolchain and matching SDKs.
