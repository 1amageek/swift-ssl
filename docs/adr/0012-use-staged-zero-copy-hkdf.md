# ADR 0012: Use staged, caller-buffer HKDF

- Status: Accepted
- Date: 2026-07-31

## Context

TLS 1.3 and HPKE require HKDF, but their label encodings are protocol constructions rather than properties of the underlying KDF. A convenience API that returns arrays would allocate secret-bearing intermediate buffers and obscure ownership. A single generic `derive` operation would also hide the pseudorandom-key boundary required by protocol key schedules.

HKDF-Expand produces at most 255 hash-length blocks. Every block after the first authenticates the preceding block, so an implementation must retain that dependency without materializing the complete output twice.

## Decision

`ExtractAndExpandKeyDerivationFunction` owns only the extract/expand semantic contract. `HKDFSHA256` is the concrete RFC 5869 SHA-256 implementation. TLS 1.3 and HPKE label construction remain the responsibility of their protocol-specific layers.

Inputs are scoped `Span<UInt8>` borrows. Extract requires an exactly 32-byte caller-owned output span, preventing an untouched suffix from being mistaken for part of the extracted pseudorandom key. Expand fills the caller's requested output span and rejects output larger than 255 SHA-256 digests before writing. Because later blocks reread the pseudorandom key and info, expand rejects either input overlapping its output before mutation; ordinary lifetime-checked spans already prevent this alias, and the runtime check protects unsafe callers.

Full expand blocks are finalized directly into their destination ranges. A completed destination block is borrowed as the previous-block input for the next HMAC operation. Only a partial final block uses one fixed 32-byte stack temporary, which is wiped before the function returns. The one-byte counter is exposed through a scoped unsafe borrow; no pointer escapes.

Expected input, overlap, and length failures are checked before output mutation. An unexpected primitive failure is preserved as a typed `HKDFError` and is never converted to success. The public protocol requires callers to discard and wipe the complete output after any non-validation failure because preceding complete blocks may already have been written.

The current implementation prepares the HMAC inner and outer SHA-256 states once per expand operation, then clones inline working contexts for each output block. Every prepared and working state is wiped at the end of its lexical scope. The public allocation-backed HMAC context remains the owner for escaping incremental use; HKDF does not construct it. Optimized code generation and runtime instrumentation must still prove the zero-allocation target rather than inferring it from the source structure. Caller input and output bytes are not copied into heap containers.

## Consequences

- Extract and expand remain independently usable by TLS, HPKE, and other modern constructions.
- The public API makes borrowed input and caller-owned secret output explicit.
- Empty salt and info use the RFC 5869 semantics without a compatibility branch.
- Zero-length output is valid, while a pseudorandom key shorter than one digest and output longer than 8160 bytes are typed failures.
- Expand rejects pseudorandom-key/output and info/output overlap before writing.
- TLS and HPKE cannot silently reinterpret their labels as raw HKDF info.
- Further midstate-copy optimization can replace the internal HMAC scheduling without changing the public protocol.

## Verification

The initial gate requires RFC 5869 SHA-256 test cases 1, 2, and 3; zero-length and maximum-length output; unchanged output on invalid extract-output size, undersized pseudorandom key, excessive expand output, and overlapping-buffer failures; Native, WASI, and Embedded WASI execution; sanitizer coverage; and generated-code inspection of the direct-block and partial-block paths.

Allocation and copy instrumentation must confirm the budget in `docs/VERIFICATION.md` before HKDF-SHA-256 is marked complete.
